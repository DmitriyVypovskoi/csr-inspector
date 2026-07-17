package csr

import "fmt"

type UnsupportedPEMTypeError struct {
	Type string
}

func (e *UnsupportedPEMTypeError) Error() string {
	return fmt.Sprintf(
		"unsupported PEM type: %q",
		e.Type,
	)
}

func (e *UnsupportedPEMTypeError) Unwrap() error {
	return ErrUnsupportedPEMType
}
