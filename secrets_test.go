package sharedsecret

import (
	"testing"
)

func TestShareSecretByShamirSchema(t *testing.T) {
	t.Run("should share secrets by 3 parts", func(t *testing.T) {
		secCtx := SecretContext{
			Bits:  8,
			Radix: 16,
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

	// []string{801c03e1a509889b41ac169e2030b89d6e4, 8029d7c34a02d0f75349fd2d90520534b5d, 8035d422ef0b586c12e5ebb3b0739eecbc1}
}

func TestShareSecretByShamirSchemaCombine(t *testing.T) {
	t.Run("should combine secrets from 3 parts", func(t *testing.T) {
		secCtx := SecretContext{
			Bits:  8,
			Radix: 16,
		}

		sh := &shareSecretByShamirSchema{
			formatter: NewShamirFullSecretFormatter(secCtx),
			secCtx:    secCtx,
		}
		sh.init(secCtx.Bits)
		got, err := sh.Combine([]string{"802d7130059ae0513ae95119bbcc090f8c1", "803329400fbf98994f95197586ca9c2af13"}, 0)
		if err != nil {
			t.Errorf("expect no error, got %v", err)
		}
		if got != "12345678" {
			t.Errorf("expect 12345678, got %v", got)
		}
	})
}
