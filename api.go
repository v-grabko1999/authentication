package authentication

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type EmailSecretKey string
type ProfileID int64
type TokenID string
type TokenLifeTime int64
type Auth struct {
	TokenLifeTimeSecond TokenLifeTime
	TokenSecretKey      []byte
	st                  DriverStorage
}

func NewAuth(st DriverStorage) *Auth {
	return &Auth{
		st: st,
	}
}

func (a *Auth) Registration(login, email, password string) (*Token, error) {
	return newToken(0), nil
}

func (a *Auth) Authentication(login, password string) (*Token, error) {
	return newToken(0), nil
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

var poolLifeTIME = newPoolLifeTime()

func (a *Auth) NewToken(tok *Token) (string, error) {
	mTok := &MarshallToken{
		ID:       TokenID(uuid.New().String()),
		LifeTime: TokenLifeTime(time.Now().Unix()) + a.TokenLifeTimeSecond,
	}

	mTok.Hash = signature(a.TokenSecretKey, []byte(mTok.ID), poolLifeTIME.Conv(mTok.LifeTime))

	bs, err := json.Marshal(mTok)
	if err != nil {
		return "", err
	}

	if err := a.st.NewToken(mTok.ID, tok.ProfileID, mTok.LifeTime); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bs), nil
}

func (a *Auth) ReadToken(token string) (*Token, error) {
	bs, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	mTok := new(MarshallToken)
	err = json.Unmarshal(bs, mTok)
	if err != nil {
		return nil, err
	}

	mtokHash := signature(a.TokenSecretKey, []byte(mTok.ID), poolLifeTIME.Conv(mTok.LifeTime))

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

func (a *Auth) DelToken(tokID TokenID, profID ProfileID) error {
	return a.st.DelToken(tokID, profID)
}

type MarshallToken struct {
	ID       TokenID
	LifeTime TokenLifeTime
	Hash     string
}

var poolHash = newPoolHash()

func signature(secret_key []byte, values ...[]byte) string {
	h := poolHash.Get()
	defer poolHash.Put(h)

	h.Write(secret_key)
	for _, value := range values {
		h.Write(value)
	}

	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}
