package authentication

type DriverStorage interface {
	NewToken(tokenID TokenID, profileID ProfileID, lifeTime TokenLifeTime) error
	ReadToken(tokenID TokenID) (ProfileID, error)
	DelToken(tokenID TokenID, profileID ProfileID) error

	IsUniqueLogin(login string) (bool, error)
	IsUniqueEmail(email string) (bool, error)

	NewProfile(login, email, password string) (ProfileID, error)
	GetPasswordByLogin(login string) (exist bool, profileID ProfileID, password string, err error)
}
