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
	/*dsn := "books:(1YAuc[z1uefCxY0@tcp(127.0.0.1:3306)/books?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal("error open mysql", err)
		return
	}
	*/
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
}

func testRegistr(auth *authentication.Auth, t *testing.T) {
	//создаем нового пользователя
	profile, err := auth.Registration("admin", "test@gmail.com", "test password")
	if err != nil {
		t.Fatal("error profile registration", err)
		return
	}
	t.Log("ok registaration profile: ", profile)
	//проверяем запрет регистрации не уникальных данных

	//не уникаьный емаил
	_, err = auth.Registration("adminлщ", "test@gmail.com", "test password")
	if err != nil {
		if errors.Is(err, authentication.ErrEmailNotUnique) {
			t.Log("ok unique email")
		} else {
			t.Fatal("error profile qnique email", err)
			return
		}
	}

	//не уникальный логин
	_, err = auth.Registration("admin", "testФЫ@gmail.com", "test password")
	if err != nil {
		if errors.Is(err, authentication.ErrLoginNotUnique) {
			t.Log("ok unique login")
		} else {
			t.Fatal("error profile qnique login", err)
			return
		}
	}
}
