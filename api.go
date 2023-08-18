package authentication

type EmailSecretKey string

type Auth struct {
}

func (a *Auth) Registration(login, email, password string) (Token, error) {
	return Token{}, nil
}

func (a *Auth) Authentication(login, password string) (Token, error) {
	return Token{}, nil
}

func (a *Auth) ForgotPassword(email string) (EmailSecretKey, error) {
	return "", nil
}

func (a *Auth) RecoveryPassword(key EmailSecretKey, newPassword string) (bool, error) {
	return true, nil
}

func (a *Auth) AllowedChangeEmail(key EmailSecretKey, newEmail string) (bool, error) {
	return true, nil
}
