package sharedsecret

import (
	"testing"
)

func TestShareSecretByShamirSchema(t *testing.T) {
	t.Run("should share secrets by 3 parts", func(t *testing.T) {
		secCtx := SecretContext{
			Bits:      8,
			Radix:     16,
			MaxShares: 256,
		}

		sh := &shareSecretByShamirSchema{
			formatter: NewShamirFullSecretFormatter(secCtx),
			secCtx:    secCtx,
		}
		sh.init(secCtx.Bits)
		got, err := sh.Share("112233445566", 3, 2, 32)
		t.Errorf("%#v %v\n", got, err)
	})

	// []string{"8015a01113e0c525543", "802b401111a4d68552c", "803ee011106727e5509"}
}

func TestShareSecretByShamirSchemaCombine(t *testing.T) {
	t.Run("should combine secrets from 3 parts", func(t *testing.T) {
		secCtx := SecretContext{
			Bits:      8,
			Radix:     16,
			MaxShares: 256,
		}

		sh := &shareSecretByShamirSchema{
			formatter: NewShamirFullSecretFormatter(secCtx),
			secCtx:    secCtx,
		}
		sh.init(secCtx.Bits)
		got, err := sh.Combine([]string{"8015a01113e0c525543", "802b401111a4d68552c", "803ee011106727e5509"}, 0)
		t.Errorf("%#v %v\n", got, err)
		//
	})
}
