package sharedsecret

import (
	"testing"
)

func TestShareSecretByShamirSchema(t *testing.T) {
	t.Run("should share secrets by 3 parts", func(t *testing.T) {
		secCtx := SecretContext{
			Bits:      8,
			Radix:     16,
			MaxShares: 128,
		}

		sh := &shareSecretByShamirSchema{
			formatter: NewShamirFullSecretFormatter(secCtx),
			secCtx:    secCtx,
		}
		sh.init(secCtx.Bits)
		got, err := sh.Share("12345678", 3, 2, 128)
		if err != nil {
			t.Errorf("expect no error, got %v", err)
		}
		if len(got) != 3 {
			t.Errorf("expect 3 parts, got %v", got)
		}
	})

	// []string{"8015a01113e0c525543", "802b401111a4d68552c", "803ee011106727e5509"}
}

func TestShareSecretByShamirSchemaCombine(t *testing.T) {
	t.Run("should combine secrets from 3 parts", func(t *testing.T) {
		secCtx := SecretContext{
			Bits:      8,
			Radix:     16,
			MaxShares: 128,
		}

		sh := &shareSecretByShamirSchema{
			formatter: NewShamirFullSecretFormatter(secCtx),
			secCtx:    secCtx,
		}
		sh.init(secCtx.Bits)
		got, err := sh.Combine([]string{"801e58700a2578c8757c486c3d17b6601aa", "802d7130059ae0513ae95119bbcc090f8c1", "803329400fbf98994f95197586ca9c2af13"}, 0)
		if err != nil {
			t.Errorf("expect no error, got %v", err)
		}
		if got != "12345678" {
			t.Errorf("expect 12345678, got %v", got)
		}
	})
}
