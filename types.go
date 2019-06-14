package sharedsecret

type (
	// SecretContext specifies data schema config
	SecretContext struct {
		Bits  int
		Radix int

		size      int
		maxShares int
	}

	shamirSharedSecretData struct {
		id   int
		bits int
		data string
	}

	// SecretShares .
	SecretShares []string

	// SecretFormatter formats and parses secret shares
	SecretFormatter interface {
		// Init .
		Init() error

		// Format .
		Format(secCtx SecretContext, secretID, data string) (string, error)

		// Parse .
		Parse(secCtx SecretContext, data string) (interface{}, error)
	}

	// ShareSecret splits and combine secret parts
	ShareSecret interface {
		// Share .
		Share(secretStr string, numShares, threshold, padLength int) ([]string, error)

		// Combine .
		Combine(shares []string, at int) (string, error)

		// NewShare .
		NewShare(id int, shares []string) (string, error)
	}
)
