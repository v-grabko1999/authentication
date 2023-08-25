package authentication

import (
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
)

type EmailSecretKey string
type ProfileID int64
type TokenID string
type TokenLifeTime int64

type AuthConfig struct {
	DriverStorage       DriverStorage
	EmailLifeTimeSecond int64
	ProfilePasswordSalt []byte
	TokenSecretKey      []byte
}

func NewAuth(cfg AuthConfig) *Auth {
	passwordHasher := new(passwordHasher)
	passwordHasher.s = sync.RWMutex{}
	passwordHasher.bs = cfg.ProfilePasswordSalt

	tokConfig := &profileConfig{
		st:             singleflightDriverStorage(cfg.DriverStorage),
		passwordHasher: passwordHasher,
		emailLifeTime:  cfg.EmailLifeTimeSecond,
	}

	return &Auth{
		st:                  cfg.DriverStorage,
		emailLifeTimeSecond: cfg.EmailLifeTimeSecond,
		tokenSecretKey:      cfg.TokenSecretKey,

		tokenConfig:         tokConfig,
		profilePasswordSalt: passwordHasher,
	}
}

type Auth struct {
	st                  DriverStorage
	emailLifeTimeSecond int64
	tokenSecretKey      []byte

	tokenConfig         *profileConfig
	profilePasswordSalt *passwordHasher
}

func (a *Auth) Registration(login, email, password string) (*Profile, error) {

	uniqueLogin, err := a.st.IsUniqueLogin(login)
	if err != nil {
		return nil, err
	}

	if !uniqueLogin {
		return nil, ErrLoginNotUnique
	}

	uniqueEmail, err := a.st.IsUniqueEmail(email)
	if err != nil {
		return nil, err
	}
	if !uniqueEmail {
		return nil, ErrEmailNotUnique
	}

	profID, err := a.st.NewProfile(login, email, a.profilePasswordSalt.Hash(login, password))
	if err != nil {
		return nil, err
	}
	return newProfile(a.tokenConfig, profID), nil
}

func (a *Auth) Authentication(login, password string) (*Profile, error) {
	res, err := a.st.GetPasswordByLogin(login)
	if err != nil {
		if err == ErrLoginNotFound {
			return nil, ErrWrongLoginOrPassword
		}
		return nil, err
	}

	if a.profilePasswordSalt.Hash(login, password) != res.Password {
		return nil, ErrWrongLoginOrPassword
	}

	return newProfile(a.tokenConfig, res.ProfileID), nil
}

func (a *Auth) ProfileByID(profileID ProfileID) (*Profile, error) {
	ok, err := a.st.ProfileExist(profileID)
	if err != nil {
		return nil, err
	}
	if ok {
		return newProfile(a.tokenConfig, profileID), nil
	} else {
		return nil, ErrProfileIdNotFound
	}
}

func (a *Auth) ForgotPassword(email string) (EmailSecretKey, error) {
	secret := EmailSecretKey(uuid.New().String())
	err := a.st.EmailNewSecretKey(secret, email, a.emailLifeTimeSecond)
	return secret, err
}

func (a *Auth) RecoveryPassword(key EmailSecretKey, newPassword string) error {
	email, err := a.st.EmailReadSecretKey(key)
	if err != nil {
		return err
	}
	login, err := a.st.GetLoginByEmail(email)
	if err != nil {
		return err
	}

	err = a.st.EmailDeleteSecretKey(key)
	if err != nil {
		return err
	}
	return a.st.SetPasswordProfileByEmail(email, a.profilePasswordSalt.Hash(login, newPassword))
}

func (a *Auth) AllowedChangeEmail(key EmailSecretKey, newEmail string) error {
	email, err := a.st.EmailReadSecretKey(key)
	if err != nil {
		return err
	}
	pid, err := a.st.GetProfileIDByEmail(email)
	if err != nil {
		return err
	}
	err = a.st.EmailDeleteSecretKey(key)
	if err != nil {
		return err
	}
	return a.st.SetEmailByProfileID(pid, newEmail)
}

type Token struct {
	ID       TokenID
	LifeTime TokenLifeTime
	Hash     string
}

var poolInt64 = NewInt64ToBytes()

func (a *Auth) NewToken(prof *Profile, tokenLifeTimeSecond TokenLifeTime) (string, error) {
	mTok := &Token{
		ID:       TokenID(uuid.New().String()),
		LifeTime: TokenLifeTime(time.Now().Unix()) + tokenLifeTimeSecond,
	}

	mTok.Hash = signature(a.tokenSecretKey, []byte(mTok.ID), poolInt64.Conv(int64(mTok.LifeTime)))
	bs, err := json.Marshal(mTok)
	if err != nil {
		return "", err
	}

	if err := a.st.NewToken(mTok.ID, prof.ProfileID, mTok.LifeTime); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bs), nil
}

func (a *Auth) ReadToken(publickToken string) (*Profile, error) {
	mTok, err := readToken(a.tokenSecretKey, publickToken)
	if err != nil {
		return nil, err
	}

	profileID, err := a.st.ReadToken(mTok.ID)
	if err != nil {
		return nil, err
	}

	return newProfile(a.tokenConfig, profileID), nil
}

func (a *Auth) DelPublicToken(publickToken string, profID ProfileID) error {
	mTok, err := readToken(a.tokenSecretKey, publickToken)
	if err != nil {
		return err
	}
	return a.st.DelToken(mTok.ID, profID)
}

func readToken(tokenSecretKey []byte, publickToken string) (*Token, error) {
	bs, err := base64.URLEncoding.DecodeString(publickToken)
	if err != nil {
		return nil, err
	}

	mTok := new(Token)
	err = json.Unmarshal(bs, mTok)
	if err != nil {
		return nil, err
	}

	mtokHash := signature(tokenSecretKey, []byte(mTok.ID), poolInt64.Conv(int64(mTok.LifeTime)))

	if mtokHash != mTok.Hash {
		return nil, ErrTokenInvalidSignature
	}

	//время жизни токена истекло
	if int64(mTok.LifeTime) < time.Now().Unix() {
		return nil, ErrTokenGoneLifeTime
	}

	return mTok, nil
}
