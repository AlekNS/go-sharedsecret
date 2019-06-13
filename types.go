package sharedsecret

type (
	// SecretContext .
	SecretContext struct {
		Bits      int
		MaxShares int
		Radix     int

		size int
	}

	shamirSharedSecretData struct {
		id   int
		bits int
		data string
	}

	// SecretShares .
	SecretShares [][]byte

	// SecretFormatter .
	SecretFormatter interface {
		// Format .
		Format(secCtx SecretContext, secretID, data string) (string, error)

		// Parse .
		Parse(secCtx SecretContext, data string) (interface{}, error)
	}

	// ShareSecret .
	ShareSecret interface {
		Share(secretStr string, numShares, threshold, padLength int) ([]string, error)
		Combine(shares []string, at int) (string, error)
		// NewShare(id int, shares []string) (string, error)
	}
)
