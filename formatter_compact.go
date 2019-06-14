package sharedsecret

import (
	"fmt"
	"math"
	"strconv"
)

type shamirSecretCompactFormatter struct {
	index int
}

func (sf *shamirSecretCompactFormatter) Format(secCtx SecretContext, secretID string, data string) (string, error) {
	if len(data) == 0 {
		return "", ErrNilEmptyData
	}

	var err error
	var idMax int

	idUval, err := strconv.ParseUint(secretID, secCtx.Radix, 32)
	id := int(idUval)
	idMax = int(math.Pow(2, float64(secCtx.Bits))) - 1
	if err != nil {
		return "", err
	}

	if id < 1 || id > idMax {
		return "", fmt.Errorf("share id must be an integer between 1 and %v, inclusive", idMax)
	}

	return data, nil
}

func (sf *shamirSecretCompactFormatter) Parse(secCtx SecretContext, data string) (interface{}, error) {
	if len(data) == 0 {
		return nil, ErrNilEmptyData
	}

	sf.index++
	if sf.index >= int(math.Pow(2, float64(secCtx.Bits)))-1 {
		sf.index = 0
	}

	return shamirSharedSecretData{
		id:   sf.index,
		bits: secCtx.Bits,
		data: data,
	}, nil
}

func (sf *shamirSecretCompactFormatter) Init() error {
	sf.index = 0
	return nil
}

// NewShamirCompactSecretFormatter .
func NewShamirCompactSecretFormatter(secCtx SecretContext) SecretFormatter {
	return new(shamirSecretCompactFormatter)
}
