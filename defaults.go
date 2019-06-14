package sharedsecret

var shamirDefaults = struct {
	bits            int // default number of bits
	radix           int // work with HEX by default
	minBits         int
	maxBits         int // this permits 1,048,575 shares, though going this high is NOT recommended!
	bytesPerChar    int
	maxBytesPerChar int // Math.pow(256,7) > Math.pow(2,53)

	// Primitive polynomials (in decimal form) for Galois Fields GF(2^n), for 2 <= n <= 30
	// The index of each term in the array corresponds to the n for that polynomial
	// i.e. to get the polynomial for n=16, use primitivePolynomials[16]
	primitivePolynomials []int
	preGenPadding        string
}{
	bits:            8,
	radix:           16,
	minBits:         3,
	maxBits:         20,
	bytesPerChar:    2,
	maxBytesPerChar: 6,

	primitivePolynomials: []int{-1, -1, 1, 3, 3, 5, 3, 3, 29, 17, 9, 5, 83, 27, 43, 3, 45, 9, 39, 39, 9, 5, 3, 33, 27, 9, 71, 39, 9, 5, 83},
}

func init() {
	shamirDefaults.preGenPadding = "00000000" // 1024 zeros
	for i := 0; i < 7; i++ {
		shamirDefaults.preGenPadding = shamirDefaults.preGenPadding + shamirDefaults.preGenPadding
	}
}
