package drivers

import (
	"time"

	"github.com/v-grabko1999/authentication"

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
	return nil
}
func (g *GormDriver) EmailReadSecretKey(key authentication.EmailSecretKey) (email string, err error) {
	return "", nil
}
func (g *GormDriver) EmailDeleteSecretKey(key authentication.EmailSecretKey) error {
	return nil
}

func (g *GormDriver) NewToken(tokenID authentication.TokenID, profileID authentication.ProfileID, lifeTime authentication.TokenLifeTime) error {
	return nil
}
func (g *GormDriver) ReadToken(tokenID authentication.TokenID) (authentication.ProfileID, error) {
	return 0, nil
}
func (g *GormDriver) DelToken(tokenID authentication.TokenID, profileID authentication.ProfileID) error {
	return nil
}

func (g *GormDriver) IsUniqueLogin(login string) (bool, error) {
	return false, nil
}
func (g *GormDriver) IsUniqueEmail(email string) (bool, error) {
	return false, nil
}

func (g *GormDriver) NewProfile(login, email, password string) (authentication.ProfileID, error) {
	return 0, nil
}
func (g *GormDriver) DelProfile(profileID authentication.ProfileID) error {
	return nil
}

func (g *GormDriver) SetPasswordProfileByEmail(email string, password string) error {
	return nil
}
func (g *GormDriver) SetPasswordProfileByProfileID(profileID authentication.ProfileID, password string) error {
	return nil
}
func (g *GormDriver) SetEmailByProfileID(profileID authentication.ProfileID, email string) error {
	return nil
}

func (g *GormDriver) GetProfileIDByEmail(email string) (profileID authentication.ProfileID, err error) {
	return 0, nil
}
func (g *GormDriver) GetPasswordByID(profileID authentication.ProfileID) (password string, err error) {
	return "", nil
}
func (g *GormDriver) GetPasswordByLogin(login string) (res *authentication.ResultPasswordByLogin, err error) {
	return
}
func (g *GormDriver) GetLoginByEmail(email string) (login string, err error) {
	return
}

func (g *GormDriver) GetEmail(profileID authentication.ProfileID) (email string, err error) {
	return
}
func (g *GormDriver) GetLogin(profileID authentication.ProfileID) (login string, err error) {
	return
}