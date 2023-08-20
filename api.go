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
	TokenLifeTimeSecond TokenLifeTime
	EmailLifeTimeSecond int64
	ProfilePasswordSalt []byte
	TokenSecretKey      []byte
}

func NewAuth(cfg AuthConfig) *Auth {
	passwordHasher := new(passwordHasher)
	passwordHasher.s = sync.RWMutex{}
	passwordHasher.bs = cfg.ProfilePasswordSalt

	tokConfig := &profileConfig{
		st:             cfg.DriverStorage,
		passwordHasher: passwordHasher,
		emailLifeTime:  cfg.EmailLifeTimeSecond,
	}

	return &Auth{
		st:                  cfg.DriverStorage,
		tokenLifeTimeSecond: cfg.TokenLifeTimeSecond,
		emailLifeTimeSecond: cfg.EmailLifeTimeSecond,
		tokenSecretKey:      cfg.TokenSecretKey,

		tokenConfig:         tokConfig,
		profilePasswordSalt: passwordHasher,
	}
}

type Auth struct {
	st                  DriverStorage
	tokenLifeTimeSecond TokenLifeTime
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
	return newToken(a.tokenConfig, profID), nil
}

func (a *Auth) Authentication(login, password string) (*Profile, error) {
	res, err := a.st.GetPasswordByLogin(login)
	if err != nil {
		return nil, err
	}

	if !res.Exist {
		return nil, ErrWrongLoginOrPassword
	}

	if a.profilePasswordSalt.Hash(login, password) != res.Password {
		return nil, ErrWrongLoginOrPassword
	}

	return newToken(a.tokenConfig, res.ProfileID), nil
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

	return a.st.SetEmailByProfileID(pid, newEmail)
}

type Token struct {
	ID       TokenID
	LifeTime TokenLifeTime
	Hash     string
}

var poolLifeTIME = newPoolLifeTime()

func (a *Auth) NewToken(prof *Profile) (string, error) {
	mTok := &Token{
		ID:       TokenID(uuid.New().String()),
		LifeTime: TokenLifeTime(time.Now().Unix()) + a.tokenLifeTimeSecond,
	}

	mTok.Hash = signature(a.tokenSecretKey, []byte(mTok.ID), poolLifeTIME.Conv(mTok.LifeTime))

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

	tok := new(Profile)
	tok.ProfileID, err = a.st.ReadToken(mTok.ID)
	if err != nil {
		return nil, err
	}

	return tok, nil
}

func (a *Auth) DelPublicToken(publickToken string, profID ProfileID) error {
	mTok, err := readToken(a.tokenSecretKey, publickToken)
	if err != nil {
		return err
	}
	return a.st.DelToken(mTok.ID, profID)
}

// @todo реализовать проверку времени жизни токена
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

	mtokHash := signature(tokenSecretKey, []byte(mTok.ID), poolLifeTIME.Conv(mTok.LifeTime))

	if mtokHash != mTok.Hash {
		return nil, ErrTokenInvalidSignature
	}

	return mTok, nil
}
