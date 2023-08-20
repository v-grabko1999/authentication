package authentication

import (
	"strings"
	"sync"

	"github.com/google/uuid"
)

type profileConfig struct {
	st             DriverStorage
	passwordHasher *passwordHasher
	emailLifeTime  int64
}

func newToken(tokCfg *profileConfig, id ProfileID) *Profile {
	return &Profile{
		cfg:       tokCfg,
		cache:     new(profileCache),
		ProfileID: id,
	}
}

type Profile struct {
	cfg       *profileConfig
	cache     *profileCache
	ProfileID ProfileID
}

type profileCache struct {
	email, login string
	s            sync.RWMutex
}

func (t *Profile) GetEmail() (string, error) {
	t.cache.s.RLock()
	count := len(t.cache.email)
	t.cache.s.RUnlock()
	if count == 0 {
		email, err := t.cfg.st.GetEmail(t.ProfileID)
		if err != nil {
			return "", err
		}

		t.cache.s.Lock()
		t.cache.email = email
		t.cache.s.Unlock()

		return email, nil
	} else {
		t.cache.s.RLock()
		defer t.cache.s.RUnlock()
		return strings.Clone(t.cache.email), nil
	}

}

func (t *Profile) GetLogin() (string, error) {
	t.cache.s.RLock()
	count := len(t.cache.login)
	t.cache.s.RUnlock()
	if count == 0 {
		login, err := t.cfg.st.GetLogin(t.ProfileID)
		if err != nil {
			return "", err
		}

		t.cache.s.Lock()
		t.cache.login = login
		t.cache.s.Unlock()

		return login, nil
	} else {
		t.cache.s.RLock()
		defer t.cache.s.RUnlock()
		return strings.Clone(t.cache.login), nil
	}
}

func (t *Profile) ChangePassword(OldPassword, NewPassword string) error {
	ok, err := t.isPassword(OldPassword)
	if err != nil {
		return err
	}

	if !ok {
		return ErrWrongPassword
	}

	login, err := t.GetLogin()
	if err != nil {
		return err
	}

	t.cfg.st.SetPasswordProfileByProfileID(t.ProfileID, t.cfg.passwordHasher.Hash(login, NewPassword))
	return nil
}

func (t *Profile) ChangeEmail(password string) (EmailSecretKey, error) {
	ok, err := t.isPassword(password)
	if err != nil {
		return "", err
	}

	if !ok {
		return "", ErrWrongPassword
	}

	email, err := t.GetEmail()
	if err != nil {
		return "", err
	}

	secret := EmailSecretKey(uuid.New().String())
	err = t.cfg.st.EmailNewSecretKey(secret, email, t.cfg.emailLifeTime)
	return secret, err
}

func (t *Profile) DeleteProfile(Password string) error {
	ok, err := t.isPassword(Password)
	if err != nil {
		return err
	}

	if !ok {
		return ErrWrongPassword
	}

	return t.cfg.st.DelProfile(t.ProfileID)
}

func (t *Profile) isPassword(password string) (bool, error) {
	pass1, err := t.cfg.st.GetPasswordByID(t.ProfileID)
	if err != nil {
		return false, err
	}

	login, err := t.GetLogin()
	if err != nil {
		return false, err
	}

	if pass1 != t.cfg.passwordHasher.Hash(login, password) {
		return false, nil
	}
	return true, nil
}
