package sharedsecret

// TransformEncryptAES .
func TransformEncryptAES() TransformFunc {
	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		if isBackwardDir {
			// decrypt
			return data, nil
		}
		// encrypt
		return data, nil
	}
}
