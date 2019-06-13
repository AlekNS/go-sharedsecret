package sharedsecret

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

type shareSecretByShamirSchema struct {
	formatter SecretFormatter
	secCtx    SecretContext

	logs []int
	exps []int
}

func (sh *shareSecretByShamirSchema) init(bits int) {
	if bits%1 != 0 || bits < shamirDefaults.minBits || bits > shamirDefaults.maxBits {
		panic(fmt.Sprintf("Number of bits must be an integer between %d and %d, inclusive.", shamirDefaults.minBits, shamirDefaults.maxBits))
	}

	sh.secCtx.Radix = shamirDefaults.radix
	sh.secCtx.Bits = bits
	if sh.secCtx.Bits == 0 {
		sh.secCtx.Bits = shamirDefaults.bits
	}

	sh.secCtx.size = int(math.Pow(2, float64(sh.secCtx.Bits)))
	sh.secCtx.MaxShares = sh.secCtx.size - 1

	var exps = make([]int, sh.secCtx.size)
	var logs = make([]int, sh.secCtx.size)

	// Construct the exp and log tables for multiplication.
	var primitive = shamirDefaults.primitivePolynomials[sh.secCtx.Bits]
	var x = 1

	for i := 0; i < sh.secCtx.size; i++ {
		exps[i] = x
		logs[x] = i
		x = x << 1 // Left shift assignment
		if x >= sh.secCtx.size {
			x = x ^ primitive           // Bitwise XOR assignment
			x = x & sh.secCtx.MaxShares // Bitwise AND assignment
		}
	}

	sh.logs = logs
	sh.exps = exps
}

// This is the basic polynomial generation and evaluation function
// for a `config.bits`-length secret (NOT an arbitrary length)
// Note: no error-checking at this stage! If `secret` is NOT
// a NUMBER less than 2^bits-1, the output will be incorrect!
func (sh *shareSecretByShamirSchema) getShares(secret int, numShares, threshold int) ([][]int, error) {
	var shares = make([][]int, numShares)
	var coeffs = make([]int, threshold)
	var err error
	var randVal uint64
	coeffs[0] = secret

	for i := 1; i < threshold; i++ {
		randVal, err = generateRandom(uint(sh.secCtx.Bits))
		if err != nil {
			return nil, err
		}
		coeffs[i] = int(randVal)
	}

	for i, l := 1, numShares+1; i < l; i++ {
		shares[i-1] = []int{i, evaluateHorner(i, coeffs, sh.logs, sh.exps, sh.secCtx.MaxShares)}
	}

	return shares, nil
}

// Divides a `secret` number String str expressed in radix `inputRadix` (optional, default 16)
// into `numShares` shares, each expressed in radix `outputRadix` (optional, default to `inputRadix`),
// requiring `threshold` number of shares to reconstruct the secret.
// Optionally, zero-pads the secret to a length that is a multiple of padLength before sharing.
func (sh *shareSecretByShamirSchema) Share(secretStr string, numShares, threshold, padLength int) ([]string, error) {
	var neededBits int
	var x = make([]string, numShares)
	var y = make([]string, numShares)
	var err error

	// Security:
	// For additional security, pad in multiples of 128 bits by default.
	// A small trade-off in larger share size to help prevent leakage of information
	// about small-ish secrets and increase the difficulty of attacking them.
	if padLength == 0 {
		padLength = 128
	}

	if numShares%1 != 0 || numShares < 2 {
		return nil, fmt.Errorf("number of shares must be an integer between 2 and 2^bits-1 (%d), inclusive", sh.secCtx.MaxShares)
	}

	if numShares > sh.secCtx.MaxShares {
		neededBits = int(math.Ceil(math.Log(float64(numShares+1)) / math.Ln2))
		return nil, fmt.Errorf("number of shares must be an integer between 2 and 2^bits-1 (%d), inclusive. To create %d shares, use at least %d bits",
			sh.secCtx.MaxShares, numShares, neededBits)
	}

	if threshold%1 != 0 || threshold < 2 {
		return nil, fmt.Errorf("threshold number of shares must be an integer between 2 and 2^bits-1 (%d), inclusive", sh.secCtx.MaxShares)
	}

	if threshold > sh.secCtx.MaxShares {
		neededBits = int(math.Ceil(math.Log(float64(threshold+1)) / math.Ln2))
		return nil, fmt.Errorf("threshold number of shares must be an integer between 2 and 2^bits-1 (%d), inclusive.  To use a threshold of %d, use at least %d bits", sh.secCtx.MaxShares, threshold, neededBits)
	}

	if threshold > numShares {
		return nil, fmt.Errorf("threshold number of shares was %d but must be less than or equal to the %d shares specified as the total to generate", threshold, numShares)
	}

	if padLength%1 != 0 || padLength < 0 || padLength > 1024 {
		return nil, fmt.Errorf("zero-pad length must be an integer between 0 and 1024 inclusive")
	}

	secretStr, err = hex2bin(secretStr) // append a 1 so that we can preserve the correct number of leading zeros in our secretStr
	if err != nil {
		return nil, err
	}
	secretStr = "1" + secretStr

	secret, err := splitNumStringToIntArray(secretStr, padLength, sh.secCtx.Bits)
	if err != nil {
		return nil, err
	}

	for i, l := 0, len(secret); i < l; i++ {
		subShares, err := sh.getShares(secret[i], numShares, threshold)

		for j := 0; j < numShares; j++ {
			if len(x[j]) == 0 {
				// x[j] = x[j] || subShares[j].x.toString(sh.radix)
				x[j] = strconv.FormatUint(uint64(subShares[j][0]), sh.secCtx.Radix)
			}

			prevYval := y[j]
			y[j], err = padLeft(strconv.FormatUint(uint64(subShares[j][1]), 2), sh.secCtx.Bits, sh.secCtx.Bits)
			if err != nil {
				return nil, err
			}

			y[j] += prevYval
		}
	}

	for i := 0; i < numShares; i++ {
		secretHex, err := bin2hex(y[i])
		if err != nil {
			return nil, err
		}

		x[i], err = sh.formatter.Format(sh.secCtx, x[i], secretHex)
		if err != nil {
			return nil, err
		}
	}

	return x, nil
}

// Generate a new share with id `id` (a number between 1 and 2^bits-1)
// `id` can be a Number or a String in the default radix (16)
// func (sh *shareSecretByShamirSchema) newShare(id int, shares []string) (string, error) {
// 	if id > -1 && len(shares) > 0 {
// 		share, err := sh.formatter.Parse(sh.secCtx, shares[0])
// 		if err != nil {
// 			return "", err
// 		}

// 		val, err := sh.Combine(shares, id)
// 		if err != nil {
// 			return "", err
// 		}

// 		return sh.formatter.Format(sh.secCtx, fmt.Sprintf("%d", id), val)
// 	}

// 	return "", errors.New("invalid 'id' or 'shares' array argument to newShare()")
// }

// Evaluates the Lagrange interpolation polynomial at x=`at` for
// individual config.bits-length segments of each share in the `shares`
// Array. Each share is expressed in base `inputRadix`. The output
// is expressed in base `outputRadix'.
func (sh *shareSecretByShamirSchema) Combine(shares []string, at int) (string, error) {
	var i int
	var idx int
	var j int
	var l int
	var len2 int
	var result = ""
	var err error
	var setBits int
	var x = make([]int, 0, len(shares))
	var y = make(map[int][]int, 0)

	for i, l = 0, len(shares); i < l; i++ {
		shareAbs, err := sh.formatter.Parse(sh.secCtx, shares[i])
		if err != nil {
			return "", err
		}
		share, ok := shareAbs.(shamirSharedSecretData)
		if !ok {
			return "", errors.New("invalid formatter parse")
		}

		// All shares must have the same bits settings.
		if setBits == 0 {
			setBits = share.bits
		} else if share.bits != setBits {
			return "", errors.New("mismatched shares: different bit settings")
		}

		// Reset everything to the bit settings of the shares.
		if sh.secCtx.Bits != setBits {
			sh.init(setBits)
		}

		// Check if this share.id is already in the Array
		// and proceed if it is not found.
		isFound := false
		for _, val := range x {
			if val == share.id {
				isFound = true
				break
			}
		}

		if !isFound {
			x = append(x, share.id)
			idx = len(x) - 1

			binData, err := hex2bin(share.data)
			if err != nil {
				return "", err
			}

			splitShare, err := splitNumStringToIntArray(binData, 0, sh.secCtx.Bits)
			if err != nil {
				return "", err
			}

			for j, len2 = 0, len(splitShare); j < len2; j++ {
				if y[j] == nil {
					y[j] = make([]int, len(shares))
				}
				// if len(y[j]) <= idx {
				// 	newY := make([]int, idx+1)
				// 	copy(newY, y[j][:idx])
				// 	y[j] = newY
				// }
				y[j][idx] = splitShare[j]
			}
		}

	}

	for i, l = 0, len(y); i < l; i++ {

		lagrangeVal := evaluatePolynomLagrange(at, x, y[i], sh.logs, sh.exps, sh.secCtx.MaxShares)
		lagrangeValBin := strconv.FormatUint(uint64(lagrangeVal), 2)

		prevResult := result
		result, err = padLeft(lagrangeValBin, sh.secCtx.Bits, sh.secCtx.Bits)
		if err != nil {
			return "", err
		}
		result += prevResult
	}

	// reconstructing the secret
	if at == 0 {
		//find the first 1
		idx = strings.Index(result, "1")
		return bin2hex(result[idx+1:])
	}

	return bin2hex(result)
}
