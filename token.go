package authentication

func newToken(st DriverStorage, pr *profilePasswordSaltTranz, id ProfileID) *Token {
	return &Token{
		st:        st,
		prSalt:    pr,
		ProfileID: id,
	}
}

type Token struct {
	st        DriverStorage
	prSalt    *profilePasswordSaltTranz
	ProfileID ProfileID
}

func (t *Token) GetEmail() (string, error) {
	return "", nil
}

func (t *Token) GetLogin() (string, error) {
	return "", nil
}

func (t *Token) ChangePassword(OldPassword, NewPassword string) error {
	return nil
}

func (t *Token) ChangeEmail(password string) (EmailSecretKey, error) {
	return "abra", nil
}

func (t *Token) DeleteProfile(Password string) error {
	return nil
}

func (t *Token) LogOut() error {
	return nil
}
