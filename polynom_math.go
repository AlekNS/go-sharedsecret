package sharedsecret

// Polynomial evaluation at `x` using Horner's Method
// NOTE: fx=fx * x + coeff[i] ->  exp(log(fx) + log(x)) + coeff[i],
//       so if fx===0, just set fx to coeff[i] because
//       using the exp/log form will result in incorrect value
func evaluateHorner(x int, coeffs, logs, exps []int, maxShares int) int {
	var logx = logs[x]
	var fx = 0
	var i = 0

	for i = len(coeffs) - 1; i >= 0; i-- {
		if fx != 0 {
			fx = exps[(logx+logs[fx])%maxShares] ^ coeffs[i]
		} else {
			fx = coeffs[i]
		}
	}

	return fx
}

// Evaluate the Lagrange interpolation polynomial at x = `at`
// using x and y Arrays that are of the same length, with
// corresponding elements constituting points on the polynomial.
func evaluatePolynomLagrange(at int, x, y []int, logs, exps []int, maxShares int) int {
	var sum = 0
	var l int
	var product int
	var i int
	var j int

	for i, l = 0, len(x); i < l; i++ {
		if y[i] != 0 {
			product = logs[y[i]]

			for j = 0; j < l; j++ {
				if i != j {
					if at == x[j] { // happens when computing a share that is in the list of shares used to compute it
						product = -1 // fix for a zero product term, after which the sum should be sum^0 = sum, not sum^1
						break
					}
					product = (product + logs[at^x[j]] - logs[x[i]^x[j]] + maxShares) % maxShares // to make sure it's not negative
				}
			}

			// though exps[-1]= undefined and undefined ^ anything = anything in
			// chrome, this behavior may not hold everywhere, so do the check
			if product != -1 {
				sum = sum ^ exps[product]
			}
		}

	}

	return sum
}
