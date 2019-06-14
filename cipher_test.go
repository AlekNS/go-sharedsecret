package sharedsecret

import (
	"reflect"
	"testing"
)

func TestTransformEncryptAES(t *testing.T) {
	t.Run("should encrypt and decrypt", func(t *testing.T) {
		tf := TransformEncryptAES([]byte("key"))
		raw := []byte("test data")

		enc, err := tf(raw, false)
		if err != nil {
			t.Fatal("expected no error, got", err)
		}
		if len(enc) < 16 {
			t.Fatal("expected latge buffer, got", enc)
		}

		dec, err := tf(enc, true)
		if err != nil {
			t.Fatal("expected no error, got", err)
		}
		if !reflect.DeepEqual(raw, dec) {
			t.Fatal("expected raw and decrypted are same, got", dec)
		}

		t.Run("should not decrypt by invalid key", func(t *testing.T) {
			tf := TransformEncryptAES([]byte("invlid key"))
			dec, err := tf(enc, true)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if reflect.DeepEqual(raw, dec) {
				t.Fatal("expected raw and decrypted are not same, got", dec)
			}
		})
	})
}
