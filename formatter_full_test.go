package sharedsecret

import (
	"reflect"
	"testing"
)

func TestShamirSecretFullFormatterFormat(t *testing.T) {
	type args struct {
		secCtx   SecretContext
		secretID string
		data     string
	}
	secCtx := SecretContext{
		Bits:  8,
		Radix: 16,
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"should error for empty secretID", args{secCtx, "", ""}, "", true},
		{"should error for empty data", args{secCtx, "23", ""}, "", true},
		{"should format shared secret", args{secCtx, "23", "abcd"}, "823abcd", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sf := &shamirSecretFullFormatter{}
			got, err := sf.Format(tt.args.secCtx, tt.args.secretID, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("shamirSecretFullFormatter.Format() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("shamirSecretFullFormatter.Format() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShamirSecretFullFormatterParse(t *testing.T) {
	type args struct {
		secCtx SecretContext
		data   string
	}
	secCtx := SecretContext{
		Bits:  8,
		Radix: 16,
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{"should error for empty", args{secCtx, ""}, nil, true},
		{"should error for empty data part", args{secCtx, "823"}, nil, true},
		{"should extract", args{secCtx, "823abcd"}, shamirSharedSecretData{
			id:   35,
			bits: 8,
			data: "abcd",
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sf := shamirSecretFullFormatter{}
			got, err := sf.Parse(tt.args.secCtx, tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("shamirSecretFullFormatter.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("shamirSecretFullFormatter.Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
