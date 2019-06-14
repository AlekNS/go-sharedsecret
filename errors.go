package sharedsecret

import "errors"

// ErrInvlidArgument raises when invalid argument was passed
var ErrInvlidArgument = errors.New("invalid argument")

// ErrNilEmptyData raises when nil or empty data was passed
var ErrNilEmptyData = errors.New("nil or empty data")
