package authentication

type DriverStorage interface {
	EmailNewSecretKey(key EmailSecretKey, email string, lifetime int64) error
	EmailReadSecretKey(key EmailSecretKey) (email string, err error)
	EmailDeleteSecretKey(key EmailSecretKey) error

	NewToken(tokenID TokenID, profileID ProfileID, lifeTime TokenLifeTime) error
	ReadToken(tokenID TokenID) (ProfileID, error)
	DelToken(tokenID TokenID, profileID ProfileID) error

	IsUniqueLogin(login string) (bool, error)
	IsUniqueEmail(email string) (bool, error)

	NewProfile(login, email, password string) (ProfileID, error)
	DelProfile(profileID ProfileID) error

	SetPasswordProfileByEmail(email string, password string) error
	SetPasswordProfileByProfileID(profileID ProfileID, password string) error
	SetEmailByProfileID(profileID ProfileID, email string) error

	GetProfileIDByEmail(email string) (profileID ProfileID, err error)
	GetPasswordByID(profileID ProfileID) (password string, err error)
	GetPasswordByLogin(login string) (res *ResultPasswordByLogin, err error)
	GetLoginByEmail(email string) (login string, err error)

	GetEmail(profileID ProfileID) (email string, err error)
	GetLogin(profileID ProfileID) (login string, err error)
}

type ResultPasswordByLogin struct {
	ProfileID ProfileID
	Password  string
}
