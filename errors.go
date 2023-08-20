package authentication

import "errors"

var (
	ErrTokenInvalidSignature = errors.New("token invalid digital signature")
	ErrWrongLoginOrPassword  = errors.New("wrong login or password")
	ErrWrongPassword         = errors.New("wrong password")

	ErrLoginNotUnique = errors.New("login is not unique")
	ErrEmailNotUnique = errors.New("email is not unique")
)
