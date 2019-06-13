package sharedsecret

import (
	"encoding/base64"
	"encoding/hex"
)

// TransformFunc .
type TransformFunc func(data []byte, direction bool) ([]byte, error)

// PipeTransform .
func PipeTransform(funcs ...TransformFunc) TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		if isBackwardDir {
			len := len(funcs)
			for inx := len - 1; inx > 0; inx-- {
				data, err := funcs[inx](data, true)
				if err != nil {
					return data, err
				}
			}
		} else {
			for _, fn := range funcs {
				data, err := fn(data, false)
				if err != nil {
					return data, err
				}
			}
		}
		return data, nil
	}
}

func InvertTransform(fn TransformFunc) TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		return fn(data, !isBackwardDir)
	}
}

// NoopTransform .
func NoopTransform() TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		return data, nil
	}
}

// Base64Transform .
func Base64Transform() TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		if isBackwardDir {
			dataStr := base64.StdEncoding.EncodeToString(data)
			return []byte(dataStr), nil
		}
		data, err := base64.StdEncoding.DecodeString(string(data))
		return data, err
	}
}

// HexTransform .
func HexTransform() TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		if isBackwardDir {
			dataStr := hex.EncodeToString(data)
			return []byte(dataStr), nil
		}
		data, err := hex.DecodeString(string(data))
		return data, err
	}
}

func TransformShare(shares []string, funcs ...TransformFunc) ([][]byte, error) {
	var results = make([][]byte, len(shares))
	for inx, share := range shares {
		result, err := funcs[inx]([]byte(share), false)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func TransformCombine(shares [][]byte, funcs ...TransformFunc) ([]string, error) {
	var results = make([]string, len(shares))
	for inx, share := range shares {
		result, err := funcs[inx]([]byte(share), true)
		if err != nil {
			return nil, err
		}
		results = append(results, string(result))
	}
	return results, nil
}
