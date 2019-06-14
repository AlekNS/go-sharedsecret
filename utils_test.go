package sharedsecret

import (
	"reflect"
	"testing"
)

func TestIndexOfIntArr(t *testing.T) {
	type args struct {
		s []int
		e int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{"should not found in empty", args{[]int{}, 2}, -1},
		{"should find", args{[]int{1, 2, 3}, 2}, 1},
		{"should not find", args{[]int{1, 2, 3}, 0}, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := indexOfIntArr(tt.args.s, tt.args.e); got != tt.want {
				t.Errorf("indexOfIntArr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateRandom(t *testing.T) {
	t.Run("should raise error for invalid bits count", func(t *testing.T) {
		_, err := generateRandom(128)
		if err != ErrInvlidArgument {
			t.Fatal("expected error, got", err)
		}
	})
	t.Run("should generate random 4 bits", func(t *testing.T) {
		largeZero := 0
		// non determenistic
		for i := 0; i < 1000; i++ {
			val, err := generateRandom(4)
			if err != nil {
				t.Fatal("expect no errors, got", err)
			}
			if val&0xFFFFFFF0 > 0 {
				t.Fatalf("expect max 4 bits, got %032bb", val)
			}
			if val > 0 {
				largeZero++
			}
		}
		if largeZero == 0 {
			t.Fatal("random generate only zeros")
		}
	})
	t.Run("should generate random 32 bits", func(t *testing.T) {
		_, err := generateRandom(32)
		if err != nil {
			t.Fatal("expect no errors, got", err)
		}
	})
}

func TestPadLeft(t *testing.T) {
	type args struct {
		str            string
		multipleOfBits int
		defaultBits    int
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"should returns empty", args{"", 8, 8}, "", false},
		{"should returns same with multbits 1", args{"01", 1, 1}, "01", false},
		{"should returns same with module by multbits", args{"0001", 4, 1}, "0001", false},
		{"should add zeros for less seq", args{"01", 4, 1}, "0001", false},
		{"should add zeros for gr seq", args{"00001", 4, 1}, "00000001", false},
		{"should error when multBits > 1024", args{"00001", 1025, 1}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := padLeft(tt.args.str, tt.args.multipleOfBits, tt.args.defaultBits)
			if (err != nil) != tt.wantErr {
				t.Errorf("padLeft() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("padLeft() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHex2bin(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"should returns empty", args{""}, "", false},
		{"should decode to utf", args{"7f"}, "01111111", false},
		{"should decode to utf with pad zeros", args{"07f"}, "000001111111", false},
		{"should error for invalid hex", args{"zz"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hex2bin(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("hex2bin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("hex2bin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBin2hex(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"should returns empty", args{""}, "", false},
		{"should decode to hex", args{"01111111"}, "7f", false},
		{"should decode to hex with pad zeros", args{"000001111111"}, "07f", false},
		{"should decode to hex pad zero", args{"00001111"}, "0f", false},
		{"should error for invalid bin", args{"zz"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := bin2hex(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("bin2hex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("bin2hex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitNumStringToIntArray(t *testing.T) {
	type args struct {
		str        string
		padLength  int
		configBits int
	}
	tests := []struct {
		name    string
		args    args
		want    []int
		wantErr bool
	}{
		{"should error empty", args{"", 16, 8}, nil, true},
		{"should error for invlid data", args{"1111111z", 16, 8}, nil, true},
		{"should split to 4 bytes", args{"1111111", 32, 8}, []int{127, 0, 0, 0}, false},
		{"should split to 2 words", args{"1111111", 32, 16}, []int{127, 0}, false},
		{"should split to 2 bytes", args{"111101111111", 16, 8}, []int{127, 15}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitNumStringToIntArray(tt.args.str, tt.args.padLength, tt.args.configBits)
			if (err != nil) != tt.wantErr {
				t.Errorf("splitNumStringToIntArray() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitNumStringToIntArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStr2hex(t *testing.T) {
	type args struct {
		str          string
		bytesPerChar int
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"should returns empty", args{"", 1}, "", false},
		{"should encode to hex 1 per byte", args{"ab", 1}, "6261", false},
		{"should encode to hex 2 per bytes", args{"аб", 2}, "04310430", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := str2hex(tt.args.str, tt.args.bytesPerChar)
			if (err != nil) != tt.wantErr {
				t.Errorf("str2hex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("str2hex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHex2str(t *testing.T) {
	type args struct {
		str          string
		bytesPerChar int
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"should returns empty", args{"", 2}, "", false},
		{"should decode 8b to str", args{"6261", 1}, "ab", false},
		{"should decode 16b to str", args{"04310430", 2}, "аб", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hex2str(tt.args.str, tt.args.bytesPerChar)
			if (err != nil) != tt.wantErr {
				t.Errorf("hex2str() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("hex2str() = %08x, want %08x", got, tt.want)
			}
		})
	}
}
