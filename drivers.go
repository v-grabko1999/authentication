package authentication

type DriverStorage interface {
	//EmailReadSecretKey должен возвращать такие стандартные ошибки:
	//authentication.ErrEmailSecretKeyNotFound - если записи с таким ключом в базе не найдено
	//authentication.ErrEmailSecretKeyNotFound - если время жизни токена истекло
	EmailReadSecretKey(key EmailSecretKey) (email string, err error)

	//EmailReadSecretKey должен возвращать такие стандартные ошибки:
	//authentication.ErrTokenNotFound - время жизни токена истекло
	//authentication.ErrTokenNotFound -  токена в базе данных не существует
	ReadToken(tokenID TokenID) (ProfileID, error)

	//GetProfileIDByEmail должен возвращать такие стандартные ошибки:
	//authentication.ErrEmailNotFound - если профиля с таким E-MAIL не существует
	GetProfileIDByEmail(email string) (profileID ProfileID, err error)

	//GetPasswordByID должен возвращать такие стандартные ошибки:
	//authentication.ErrProfileIdNotFound - если профиля с таким ID не существует
	GetPasswordByID(profileID ProfileID) (password string, err error)

	//GetPasswordByLogin должен возвращать такие стандартные ошибки:
	//authentication.ErrLoginNotFound - если профиля с таким логином не существует
	GetPasswordByLogin(login string) (res *ResultPasswordByLogin, err error)

	//GetLoginByEmail должен возвращать такие стандартные ошибки:
	//authentication.ErrEmailNotFound - если профиля с таким E-MAIL не существует
	GetLoginByEmail(email string) (login string, err error)

	//GetEmail должен возвращать такие стандартные ошибки:
	//authentication.ErrProfileIdNotFound - если профиля с таким ID не существует
	GetEmail(profileID ProfileID) (email string, err error)

	//GetLogin должен возвращать такие стандартные ошибки:
	//authentication.ErrProfileIdNotFound - если профиля с таким ID не существует
	GetLogin(profileID ProfileID) (login string, err error)

	EmailNewSecretKey(key EmailSecretKey, email string, lifetime int64) error
	EmailDeleteSecretKey(key EmailSecretKey) error
	NewToken(tokenID TokenID, profileID ProfileID, lifeTime TokenLifeTime) error
	DelToken(tokenID TokenID, profileID ProfileID) error
	IsUniqueLogin(login string) (bool, error)
	IsUniqueEmail(email string) (bool, error)

	NewProfile(login, email, password string) (ProfileID, error)
	DelProfile(profileID ProfileID) error

	SetPasswordProfileByEmail(email string, password string) error
	SetPasswordProfileByProfileID(profileID ProfileID, password string) error
	SetEmailByProfileID(profileID ProfileID, email string) error
}

type ResultPasswordByLogin struct {
	ProfileID ProfileID
	Password  string
}
