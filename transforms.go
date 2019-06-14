package sharedsecret

import (
	"encoding/base64"
	"encoding/hex"
)

// TransformFunc is a function for reversible transforms of a data
type TransformFunc func(data []byte, direction bool) ([]byte, error)

// PipeTransform takes set of function and apply them sequentially
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

// InvertTransform inverts transformation of function
func InvertTransform(fn TransformFunc) TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		return fn(data, !isBackwardDir)
	}
}

// NoopTransform no transforms performed
func NoopTransform() TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		return data, nil
	}
}

// Base64Transform base64 transforms
func Base64Transform() TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		if isBackwardDir {
			data, err := base64.StdEncoding.DecodeString(string(data))
			return data, err
		}
		return []byte(base64.StdEncoding.EncodeToString(data)), nil
	}
}

// HexTransform hex transforms
func HexTransform() TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		if isBackwardDir {
			data, err := hex.DecodeString(string(data))
			return data, err
		}
		return []byte(hex.EncodeToString(data)), nil
	}
}

// TransformShare takes secret shares and apply transform funcs on them
func TransformShare(shares SecretShares, funcs ...TransformFunc) ([][]byte, error) {
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

// TransformCombine takes transformed secret shares and apply backward transforms funcs on them
func TransformCombine(shares [][]byte, funcs ...TransformFunc) (SecretShares, error) {
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
