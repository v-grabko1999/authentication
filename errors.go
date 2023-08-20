package authentication

import "errors"

var (
	ErrTokenInvalidSignature = errors.New("token invalid digital signature")
)
