package drivers

import (
	"errors"
	"time"

	"github.com/v-grabko1999/authentication"

	_ "gorm.io/driver/mysql"
	_ "gorm.io/driver/postgres"
	_ "gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type GormProfileModel struct {
	ID       int64  `gorm:"primarykey"`
	Login    string `gorm:"size:255;uniqueIndex"`
	Email    string `gorm:"size:255;uniqueIndex"`
	Password string `gorm:"size:225"`

	CreatedAt time.Time
	UpdatedAt time.Time
}

type GormTokenModel struct {
	Key      string `gorm:"primarykey;size:36;autoIncrement:false"`
	Expiries int64

	ProfileID int64
	Profile   GormProfileModel `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type GormEmailSecretKeyModel struct {
	Key      string `gorm:"primarykey;size:36;autoIncrement:false"`
	Email    string `gorm:"size:255;"`
	Expiries int64
}

func (model *GormEmailSecretKeyModel) read(db *gorm.DB, key authentication.EmailSecretKey) error {
	err := db.Where("key = ?", string(key)).First(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return authentication.ErrEmailSecretKeyNotFound
		} else {
			return err
		}
	}
	return nil
}

func NewGorm(db *gorm.DB) (authentication.DriverStorage, error) {
	err := db.AutoMigrate(&GormProfileModel{}, &GormTokenModel{}, &GormEmailSecretKeyModel{})
	if err != nil {
		return nil, err
	}
	dr := new(GormDriver)
	dr.db = db
	return dr, nil
}

type GormDriver struct {
	db *gorm.DB
}

func (g *GormDriver) EmailNewSecretKey(key authentication.EmailSecretKey, email string, lifetime int64) error {
	return g.db.Create(&GormEmailSecretKeyModel{
		Key:      string(key),
		Email:    email,
		Expiries: time.Now().Unix() + lifetime,
	}).Error
}

func (g *GormDriver) EmailReadSecretKey(key authentication.EmailSecretKey) (string, error) {
	model := &GormEmailSecretKeyModel{}
	err := model.read(g.db, key)
	if err != nil {
		return "", err
	}
	//время жизни секретного ключа истекло
	if model.Expiries < time.Now().Unix() {
		if err := g.EmailDeleteSecretKey(key); err != nil {
			return "", err
		}
		return "", authentication.ErrEmailSecretKeyNotFound
	}

	return model.Email, err
}

func (g *GormDriver) EmailDeleteSecretKey(key authentication.EmailSecretKey) error {
	return g.db.Delete(&GormEmailSecretKeyModel{Key: string(key)}).Error
}

func (g *GormDriver) NewToken(tokenID authentication.TokenID, profileID authentication.ProfileID, lifeTime authentication.TokenLifeTime) error {
	return g.db.Create(&GormTokenModel{
		Key:       string(tokenID),
		Expiries:  time.Now().Unix() + int64(lifeTime),
		ProfileID: int64(profileID),
	}).Error
}

func (model *GormTokenModel) read(db *gorm.DB, tokenID authentication.TokenID) error {
	err := db.Where("key = ?", string(tokenID)).First(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = authentication.ErrTokenNotFound
		}
	}
	return err
}

func (g *GormDriver) ReadToken(tokenID authentication.TokenID) (authentication.ProfileID, error) {
	model := &GormTokenModel{}
	err := model.read(g.db, tokenID)

	//время жизни токена истекло
	if model.Expiries < time.Now().Unix() {
		if err := g.DelToken(tokenID, authentication.ProfileID(model.ProfileID)); err != nil {
			return 0, err
		}
		return 0, authentication.ErrTokenNotFound
	}

	return authentication.ProfileID(model.ProfileID), err
}

func (g *GormDriver) DelToken(tokenID authentication.TokenID, profileID authentication.ProfileID) error {
	return g.db.Delete(&GormTokenModel{Key: string(tokenID)}).Error
}

func (g *GormDriver) NewProfile(login, email, password string) (authentication.ProfileID, error) {
	model := &GormProfileModel{
		Login:    login,
		Email:    email,
		Password: password,
	}
	err := g.db.Create(model).Error
	return authentication.ProfileID(model.ID), err
}

func (g *GormDriver) DelProfile(profileID authentication.ProfileID) error {
	return g.db.Delete(&GormProfileModel{ID: int64(profileID)}).Error
}

func (g *GormDriver) SetPasswordProfileByEmail(email string, password string) error {
	return g.db.Model(&GormProfileModel{}).Where("email = ?", email).Update("password", password).Error
}

func (g *GormDriver) SetPasswordProfileByProfileID(profileID authentication.ProfileID, password string) error {
	return g.db.Model(&GormProfileModel{}).Where("id = ?", int64(profileID)).Update("password", password).Error
}
func (g *GormDriver) SetEmailByProfileID(profileID authentication.ProfileID, email string) error {
	return g.db.Model(&GormProfileModel{}).Where("id = ?", int64(profileID)).Update("email", email).Error
}

func (g *GormDriver) GetProfileIDByEmail(email string) (profileID authentication.ProfileID, err error) {
	model := &GormProfileModel{}
	err = g.db.Select("id").Where("email = ?", email).First(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = authentication.ErrEmailNotFound
		}
	}
	profileID = authentication.ProfileID(model.ID)
	return
}

func (g *GormDriver) GetPasswordByID(profileID authentication.ProfileID) (password string, err error) {
	model := &GormProfileModel{}
	err = g.db.Select("password").Where("id = ?", int64(profileID)).First(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = authentication.ErrProfileIdNotFound
		}
	}
	password = model.Password
	return
}

func (g *GormDriver) GetPasswordByLogin(login string) (res *authentication.ResultPasswordByLogin, err error) {
	model := &GormProfileModel{}
	err = g.db.Select([]string{"id", "password"}).Where("login = ?", login).First(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = authentication.ErrLoginNotFound
		}
	}
	res = &authentication.ResultPasswordByLogin{
		ProfileID: authentication.ProfileID(model.ID),
		Password:  model.Password,
	}
	return
}

func (g *GormDriver) GetLoginByEmail(email string) (login string, err error) {
	model := &GormProfileModel{}
	err = g.db.Select("login").Where("email = ?", email).First(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = authentication.ErrEmailNotFound
		}
	}
	login = model.Login
	return
}

func (g *GormDriver) ProfileExist(profileID authentication.ProfileID) (exists bool, err error) {
	err = g.db.Model(&GormProfileModel{}).Select("count(*) > 0").Limit(1).Where("id = ?", int64(profileID)).Find(&exists).Error
	return
}

func (g *GormDriver) IsUniqueLogin(login string) (exists bool, err error) {
	err = g.db.Model(&GormProfileModel{}).Select("count(*) == 0").Limit(1).Where("login = ?", login).Find(&exists).Error
	return
}

func (g *GormDriver) IsUniqueEmail(email string) (exists bool, err error) {
	err = g.db.Model(&GormProfileModel{}).Select("count(*) == 0").Limit(1).Where("email = ?", email).Find(&exists).Error
	return
}

func (g *GormDriver) GetEmail(profileID authentication.ProfileID) (email string, err error) {
	model := &GormProfileModel{}
	err = g.db.Select("email").Where("id = ?", int64(profileID)).First(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = authentication.ErrProfileIdNotFound
		}
	}
	email = model.Email
	return
}

func (g *GormDriver) GetLogin(profileID authentication.ProfileID) (login string, err error) {
	model := &GormProfileModel{}
	err = g.db.Select("login").Where("id = ?", int64(profileID)).First(model).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = authentication.ErrProfileIdNotFound
		}
	}
	login = model.Login
	return
}
