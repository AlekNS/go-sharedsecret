package sharedsecret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

// TransformEncryptAES .
func TransformEncryptAES(key []byte) TransformFunc {
	keyHash := sha256.Sum256(key)

	return func(data []byte, isBackwardDir bool) ([]byte, error) {
		c, err := aes.NewCipher(keyHash[:])
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(c)
		if err != nil {
			return data, nil
		}

		if isBackwardDir {
			// decrypt
			nonceSize := gcm.NonceSize()
			if len(data) < nonceSize {
				return nil, ErrInvlidArgument
			}

			nonce, ciphertext := data[:nonceSize], data[nonceSize:]

			return gcm.Open(nil, nonce, ciphertext, nil)
		}

		// encrypt
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		return gcm.Seal(nonce, nonce, data, nil), nil
	}
}
