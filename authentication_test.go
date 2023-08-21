package authentication_test

import (
	"testing"

	"github.com/v-grabko1999/authentication"
	"github.com/v-grabko1999/authentication/drivers"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestGormDriver(t *testing.T) {
	/*db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&foreign_keys=on"), &gorm.Config{})
	if err != nil {
		t.Fatal("error open sqlLite", err)
		return
	}*/
	dsn := "books:(1YAuc[z1uefCxY0@tcp(127.0.0.1:3306)/books?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal("error open mysql", err)
		return
	}

	dr, err := drivers.NewGorm(db)
	if err != nil {
		t.Fatal("error new gorm driver", err)
		return
	}

	authentication.NewAuth(authentication.AuthConfig{
		DriverStorage:       authentication.RunSingleflightDriverStorage(dr),
		EmailLifeTimeSecond: 60 * 60 * 24,
		ProfilePasswordSalt: []byte("test password salt"),
		TokenSecretKey:      []byte("token secret keu"),
	})

	t.Log("ok init authentication module")
	/*
		//регистрация и аутентификация
		_, err = a.Registration("admin", "admin@gmail.com", "test password")
		if err != nil {
			t.Fatal("Registration", err)
			return
		}

		profile, err := a.Authentication("admin", "test password")
		if err != nil {
			t.Fatal("Authentication", err)
			return
		}

		email, err := profile.GetEmail()
		if err != nil {
			t.Fatal("GetEmail", err)
			return
		}

		if email != "admin@gmail.com" {

		}
		profile.GetLogin()
		profile.ChangePassword("test password", "new pass")

		//смена email
		secretEmail, err := profile.ChangeEmail("new pass")
		a.AllowedChangeEmail(secretEmail, "testNewEmail@gmail.com")

		//создание, чтение и удаление токена
		token, err := a.NewToken(profile)
		profile, err = a.ReadToken(token)
		a.DelPublicToken(token, profile.ProfileID)

		//востанновление пароля
		secretEmail, err = a.ForgotPassword("admin@gmail.com")
		err = a.RecoveryPassword(secretEmail, "new test password")

		//удаление профиля
		profile.DeleteProfile("new test password")
	*/
}
