package sharedsecret

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"strconv"
)

func indexOfIntArr(s []int, e int) int {
	for i, a := range s {
		if a == e {
			return i
		}
	}
	return -1
}

func generateRandom(bits uint) (uint64, error) {
	if bits < 1 || bits > 64 {
		return 0, ErrInvlidArgument
	}
	b := make([]byte, (bits-1)/8+1)
	_, err := rand.Read(b)
	// _ != len(byte) if err != nil
	if err != nil {
		return 0, err
	}

	var n = uint64(b[0])
	for i := 1; i < len(b); i++ {
		n <<= 8
		n |= uint64(b[i])
	}
	return n & ((1 << bits) - 1), nil
}

func padLeft(str string, multipleOfBits, defaultBits int) (string, error) {
	var missing int
	var outStr string

	if multipleOfBits == 0 || multipleOfBits == 1 {
		return str, nil
	}

	if multipleOfBits > 1024 {
		return "", errors.New("padding must be multiples of no larger than 1024 bits")
	}

	if multipleOfBits == 0 {
		multipleOfBits = defaultBits
	}

	if len(str) > 0 {
		missing = len(str) % multipleOfBits
	}

	if missing > 0 {
		outStr = shamirDefaults.preGenPadding + str
		return outStr[len(outStr)-len(str)-multipleOfBits+missing:], nil
	}

	return str, nil
}

func hex2bin(str string) (string, error) {
	var bin string
	var num uint64
	var i int
	var err error

	for i = len(str) - 1; i >= 0; i-- {
		num, err = strconv.ParseUint(str[i:i+1], 16, 32)

		if err != nil {
			return "", err
		}

		bin = fmt.Sprintf("%04b", num) + bin
	}

	return bin, nil
}

func bin2hex(str string) (string, error) {
	var hex string
	var num uint64
	var i int
	var err error

	str, err = padLeft(str, 4, 4)
	if err != nil {
		return "", err
	}

	for i = len(str); i >= 4; i -= 4 {
		num, err = strconv.ParseUint(str[i-4:i], 2, 32)
		if err != nil {
			return "", err
		}
		hex = fmt.Sprintf("%x", num) + hex
	}

	return hex, nil
}

func splitNumStringToIntArray(str string, padLength, configBits int) ([]int, error) {
	var parts = make([]int, 0, 32)
	var i int
	var err error
	var num uint64

	if padLength > 0 {
		str, err = padLeft(str, padLength, padLength)
		if err != nil {
			return nil, err
		}
	}

	for i = len(str); i > configBits; i -= configBits {
		num, err = strconv.ParseUint(str[i-configBits:i], 2, configBits)
		if err != nil {
			return nil, err
		}

		parts = append(parts, int(num))
	}

	num, err = strconv.ParseUint(str[0:i], 2, configBits)
	if err != nil {
		return nil, err
	}

	parts = append(parts, int(num))

	return parts, nil
}

func str2hex(str string, bytesPerChar int) (string, error) {
	var hexChars int
	var max int
	var out string
	var outPadded string
	var neededBytes int
	var num int
	var i int
	var l int
	var err error
	var strRunes = []rune(str)

	if bytesPerChar == 0 {
		bytesPerChar = shamirDefaults.bytesPerChar
	}

	if bytesPerChar < 1 || bytesPerChar > shamirDefaults.maxBytesPerChar || bytesPerChar%1 != 0 {
		return "", fmt.Errorf("bytes per character must be an integer between 1 and %d, inclusive", shamirDefaults.maxBytesPerChar)
	}

	hexChars = 2 * bytesPerChar
	max = int(math.Pow(16, float64(hexChars)) - 1)

	for i, l = 0, len(strRunes); i < l; i++ {
		num = int(rune(strRunes[i]))

		if num >= math.MaxInt32 {
			return "", fmt.Errorf("invalid character: %x", strRunes[i])
		}

		if num > max {
			neededBytes = int(math.Ceil(math.Log(float64(num+1)) / math.Log(256)))
			return "", fmt.Errorf("invalid character code (%d). Maximum allowable is 256^bytes-1 (%d). To convert this character, use at least %d bytes", num, max, neededBytes)
		}

		outPadded, err = padLeft(fmt.Sprintf("%x", num), hexChars, hexChars)
		if err != nil {
			return "", err
		}
		out = outPadded + out
	}

	return out, nil
}

// Converts a given HEX number string to a UTF16 character string.
func hex2str(str string, bytesPerChar int) (string, error) {
	var hexChars int
	var out string
	var i int
	var l int
	var err error
	var num int64

	if bytesPerChar == 0 {
		bytesPerChar = shamirDefaults.bytesPerChar
	}

	if bytesPerChar%1 != 0 || bytesPerChar < 1 || bytesPerChar > shamirDefaults.maxBytesPerChar {
		return "", fmt.Errorf("bytes per character must be an integer between 1 and %d, inclusive", shamirDefaults.maxBytesPerChar)
	}

	hexChars = 2 * bytesPerChar

	str, err = padLeft(str, hexChars, hexChars)

	for i, l = 0, len(str); i < l; i += hexChars {
		num, err = strconv.ParseInt(str[i:i+hexChars], 16, 32)
		if err != nil {
			return "", err
		}
		out = string(rune(num)) + out
	}

	return out, nil
}
