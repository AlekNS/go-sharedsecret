package sharedsecret

import (
	"reflect"
	"testing"
)

func TestBase64Transform(t *testing.T) {
	t.Run("should forward transform", func(t *testing.T) {
		tf := Base64Transform()
		src := []byte("text")

		result, err := tf(src, false)
		if err != nil {
			t.Fatal("expected no error, got", err)
		}
		if !reflect.DeepEqual(result, []byte("dGV4dA==")) {
			t.Fatal("expected equals with const value, got", result)
		}
	})
}

func TestHexransform(t *testing.T) {
	t.Run("should forward transform", func(t *testing.T) {
		tf := HexTransform()
		src := []byte("text")

		result, err := tf(src, false)
		if err != nil {
			t.Fatal("expected no error, got", err)
		}
		if !reflect.DeepEqual(result, []byte("74657874")) {
			t.Fatalf("expected equals with const value, got %v", result)
		}
	})
}
