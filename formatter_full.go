package sharedsecret

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
)

type shamirSecretFullFormatter struct{}

func (sf *shamirSecretFullFormatter) Format(secCtx SecretContext, secretID string, data string) (string, error) {
	var err error
	var bitsBase36 string
	var idHex string
	var idMax int
	var idPaddingLen int

	idUval, err := strconv.ParseUint(secretID, secCtx.Radix, 32)
	id := int(idUval)
	bitsBase36 = strconv.FormatUint(uint64(secCtx.Bits), 36)
	idMax = int(math.Pow(2, float64(secCtx.Bits))) - 1
	idPaddingLen = len(strconv.FormatUint(uint64(idMax), secCtx.Radix))
	idHex, err = padLeft(strconv.FormatUint(uint64(id), secCtx.Radix), idPaddingLen, idPaddingLen)
	if err != nil {
		return "", err
	}

	if id%1 != 0 || id < 1 || id > idMax {
		return "", fmt.Errorf("share id must be an integer between 1 and %v, inclusive", idMax)
	}

	return bitsBase36 + idHex + data, nil
}

// Given a public share, extract the bits (Integer), share ID (Integer), and share data (Hex)
// and return an Object containing those components.
func (sf shamirSecretFullFormatter) Parse(secCtx SecretContext, data string) (interface{}, error) {
	var bits int
	var id int
	var idLen int
	var max int

	// Extract the first char which represents the bits in Base 36
	uval, err := strconv.ParseUint(data[:1], 36, 8)
	if err != nil {
		return nil, err
	}
	bits = int(uval)

	if bits%1 != 0 || bits < shamirDefaults.minBits || bits > shamirDefaults.maxBits {
		return nil, fmt.Errorf("invalid share : number of bits must be an integer between %d and %d, inclusive", shamirDefaults.minBits, shamirDefaults.maxBits)
	}

	// calc the max shares allowed for given bits
	max = int(math.Pow(2, float64(bits)) - 1)

	// Determine the ID length which is variable and based on the bit count.
	idLen = len(strconv.FormatUint(uint64(math.Pow(2, float64(bits))-1), secCtx.Radix))

	// Extract all the parts now that the segment sizes are known.
	regExp := regexp.MustCompile(fmt.Sprintf("^([a-kA-K3-9]{1})([a-fA-F0-9]{%d})([a-fA-F0-9]+)$", idLen))
	shareComponents := regExp.FindAllStringSubmatch(data, -1)

	// The ID is a Hex number and needs to be converted to an Integer
	if len(shareComponents) > 0 {
		uval, err = strconv.ParseUint(shareComponents[0][2], secCtx.Radix, 32)
		id = int(uval)
	}

	if id%1 != 0 || id < 1 || id > max {
		return nil, fmt.Errorf("invalid share : Share id must be an integer between 1 and %d, inclusive", secCtx.MaxShares)
	}

	if len(shareComponents) > 0 && len(shareComponents[0]) > 2 {
		return shamirSharedSecretData{
			id:   id,
			bits: bits,
			data: shareComponents[0][3],
		}, nil
	}

	return nil, fmt.Errorf("the share data provided is invalid: %x", data)
}

// NewShamirFullSecretFormatter .
func NewShamirFullSecretFormatter(secCtx SecretContext) SecretFormatter {
	return new(shamirSecretFullFormatter)
}
