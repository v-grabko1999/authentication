package authentication_test

import (
	"errors"
	"testing"

	"github.com/v-grabko1999/authentication"
	"github.com/v-grabko1999/authentication/drivers"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGormDriver(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&foreign_keys=on"), &gorm.Config{})
	if err != nil {
		t.Fatal("error open sqlLite", err)
		return
	}

	dr, err := drivers.NewGorm(db)
	if err != nil {
		t.Fatal("error new gorm driver", err)
		return
	}

	auth := authentication.NewAuth(authentication.AuthConfig{
		DriverStorage:       authentication.RunSingleflightDriverStorage(dr),
		EmailLifeTimeSecond: 60 * 60 * 24,
		ProfilePasswordSalt: []byte("test password salt"),
		TokenSecretKey:      []byte("token secret keu"),
	})

	t.Log("ok init authentication module")
	testLogic(auth, t)
}

func testLogic(auth *authentication.Auth, t *testing.T) {
	testRegistr(auth, t)
	profile := testAuth(auth, t)
	testProfile(profile, auth, t)
	testToken(profile, auth, t)
}

const (
	regEmail = "test@gmail.com"
	regLogin = "admin"
	regPass  = "test password"

	changeEmail    = "newAdmin@gmail.com"
	changePassword = "new test password"
)

func testRegistr(auth *authentication.Auth, t *testing.T) {
	//создаем нового пользователя
	profile, err := auth.Registration(regLogin, regEmail, regPass)
	if err != nil {
		t.Fatal("error profile registration", err)
		return
	}
	t.Log("ok registaration profile: ", profile)
	//проверяем запрет регистрации не уникальных данных

	//не уникаьный емаил
	_, err = auth.Registration("adminлщ", regEmail, regPass)
	if err != nil {
		if errors.Is(err, authentication.ErrEmailNotUnique) {
			t.Log("ok unique email")
		} else {
			t.Fatal("error profile qnique email", err)
			return
		}
	}

	//не уникальный логин
	_, err = auth.Registration(regLogin, "testФЫ@gmail.com", regPass)
	if err != nil {
		if errors.Is(err, authentication.ErrLoginNotUnique) {
			t.Log("ok unique login")
		} else {
			t.Fatal("error profile qnique login", err)
			return
		}
	}
}

func testAuth(auth *authentication.Auth, t *testing.T) *authentication.Profile {
	//неверный пароль
	_, err := auth.Authentication(regLogin, "абра")
	if err != nil {
		if errors.Is(err, authentication.ErrWrongLoginOrPassword) {
			t.Log("Authentication wrong password")
		} else {
			t.Fatal("Authentication wrong password error: ", err)
		}
	} else {
		t.Fatal("Authentication wrong password error: error == nil")
	}

	//неверный логин
	_, err = auth.Authentication("абра", regPass)
	if err != nil {
		if errors.Is(err, authentication.ErrWrongLoginOrPassword) {
			t.Log("Authentication wrong login")
		} else {
			t.Fatal("Authentication wrong login error: ", err)
		}
	} else {
		t.Fatal("Authentication wrong login error: error == nil")
	}

	profile, err := auth.Authentication(regLogin, regPass)
	if err != nil {
		t.Fatal("Authentication error: ", err)
	}
	t.Log("Ok Authentication profile: ", profile)

	login, err := profile.GetLogin()
	if err != nil {
		t.Fatal("profile.GetLogin: ", err)
	}
	email, err := profile.GetEmail()
	if err != nil {
		t.Fatal("profile.GetEmail: ", err)
	}

	if login != regLogin {
		t.Fatal("getLogin != regLogin")
	}

	if email != regEmail {
		t.Fatal("getEmail != regEmail")
	}

	return profile
}

func testProfile(prof *authentication.Profile, auth *authentication.Auth, t *testing.T) {
	if prof.ProfileID == 0 {
		t.Fatal("profile invalid ID")
	}
	//смена email
	emailSecretKey, err := prof.ChangeEmail(regPass)
	if err != nil {
		t.Fatal("profile ChangeEmail error: ", err)
	}

	err = auth.AllowedChangeEmail(emailSecretKey, changeEmail)
	if err != nil {
		t.Fatal("profile auth.AllowedChangeEmail error: ", err)
	}

	email, err := prof.GetEmail()
	if err != nil {
		t.Fatal("profile prof.GetEmail error: ", err)
	}

	if email != changeEmail {
		t.Fatal("profile email != changeEmail: ", err)
	}

	err = prof.ChangePassword(regPass, changePassword)
	if err != nil {
		t.Fatal("profile ChangePassword error: ", err)
	}
}

func testToken(prof *authentication.Profile, auth *authentication.Auth, t *testing.T) {
	tok, err := auth.NewToken(prof, 20)
	if err != nil {
		t.Fatal("testToken newToken error:", tok)
	}

	newProfile, err := auth.ReadToken(tok)
	if err != nil {
		t.Fatal("testToken ReadToken error:", tok)
	}

	if prof.ProfileID != newProfile.ProfileID {
		t.Fatal("testToken prof.ProfileID != newProfile.ProfileID")
	}
	t.Log("OK test token")
}
