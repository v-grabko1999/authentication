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
	ProfilePasswordSalt []byte
	TokenSecretKey      []byte
}

func NewAuth(cfg AuthConfig) *Auth {
	profilePasswordSalt := new(profilePasswordSaltTranz)
	profilePasswordSalt.s = sync.RWMutex{}
	profilePasswordSalt.bs = cfg.ProfilePasswordSalt

	return &Auth{
		st:                  cfg.DriverStorage,
		tokenLifeTimeSecond: cfg.TokenLifeTimeSecond,
		profilePasswordSalt: profilePasswordSalt,
		tokenSecretKey:      cfg.TokenSecretKey,
	}
}

type Auth struct {
	st                  DriverStorage
	tokenLifeTimeSecond TokenLifeTime
	profilePasswordSalt *profilePasswordSaltTranz
	tokenSecretKey      []byte
}

func (a *Auth) Registration(login, email, password string) (*Token, error) {

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
	return newToken(a.st, a.profilePasswordSalt, profID), nil
}

func (a *Auth) Authentication(login, password string) (*Token, error) {
	exist, profileID, passHash1, err := a.st.GetPasswordByLogin(login)
	if err != nil {
		return nil, err
	}

	if !exist {
		return nil, ErrWrongLoginOrPassword
	}

	if a.profilePasswordSalt.Hash(login, password) != passHash1 {
		return nil, ErrWrongLoginOrPassword
	}

	return newToken(a.st, a.profilePasswordSalt, profileID), nil
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

type MarshallPublicToken struct {
	ID       TokenID
	LifeTime TokenLifeTime
	Hash     string
}

var poolLifeTIME = newPoolLifeTime()

func (a *Auth) NewPublicToken(tok *Token) (string, error) {
	mTok := &MarshallPublicToken{
		ID:       TokenID(uuid.New().String()),
		LifeTime: TokenLifeTime(time.Now().Unix()) + a.tokenLifeTimeSecond,
	}

	mTok.Hash = signature(a.tokenSecretKey, []byte(mTok.ID), poolLifeTIME.Conv(mTok.LifeTime))

	bs, err := json.Marshal(mTok)
	if err != nil {
		return "", err
	}

	if err := a.st.NewToken(mTok.ID, tok.ProfileID, mTok.LifeTime); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bs), nil
}

func (a *Auth) ReadPublicToken(token string) (*Token, error) {
	bs, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	mTok := new(MarshallPublicToken)
	err = json.Unmarshal(bs, mTok)
	if err != nil {
		return nil, err
	}

	mtokHash := signature(a.tokenSecretKey, []byte(mTok.ID), poolLifeTIME.Conv(mTok.LifeTime))

	if mtokHash != mTok.Hash {
		return nil, ErrTokenInvalidSignature
	}

	tok := new(Token)
	tok.ProfileID, err = a.st.ReadToken(mTok.ID)
	if err != nil {
		return nil, err
	}

	return tok, nil
}

func (a *Auth) DelPublicToken(tokID TokenID, profID ProfileID) error {
	return a.st.DelToken(tokID, profID)
}
