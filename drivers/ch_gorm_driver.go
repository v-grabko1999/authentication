package drivers

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/v-grabko1999/authentication"
	"github.com/v-grabko1999/cache"
	"gorm.io/gorm"
)

func NewChGorm(ch *cache.Cache, db *gorm.DB) (authentication.DriverStorage, error) {
	err := db.AutoMigrate(&GormProfileModel{}, &GormTokenModel{}, &GormEmailSecretKeyModel{})
	if err != nil {
		return nil, err
	}
	dr := new(ChGormDriver)
	dr.db = db
	dr.cache = ch
	dr.poolInt64 = authentication.NewInt64ToBytes()
	return dr, nil
}

type ChGormDriver struct {
	GormDriver
	cache     *cache.Cache
	poolInt64 *authentication.Int64ToBytes
}

func (ch *ChGormDriver) EmailNewSecretKey(key authentication.EmailSecretKey, email string, lifetime int64) error {
	err := ch.GormDriver.EmailNewSecretKey(key, email, lifetime)
	if err != nil {
		return err
	}
	err = ch.cache.Set([]byte(key), []byte(email), int(lifetime))
	return err
}

func (ch *ChGormDriver) EmailReadSecretKey(key authentication.EmailSecretKey) (string, error) {
	bsKey := []byte(key)
	val, exist, err := ch.cache.Get(bsKey)
	if err != nil {
		return "", err
	}

	if exist {
		return string(val), nil
	}

	model := &GormEmailSecretKeyModel{}
	err = model.read(ch.db, key)
	if err != nil {
		return "", err
	}

	if model.Expiries < time.Now().Unix() {
		if err := ch.EmailDeleteSecretKey(key); err != nil {
			return "", err
		}
		return "", authentication.ErrEmailSecretKeyNotFound
	}

	return model.Email, ch.cache.Set(bsKey, []byte(model.Email), int(model.Expiries-time.Now().Unix()))
}

func (ch *ChGormDriver) EmailDeleteSecretKey(key authentication.EmailSecretKey) error {
	err := ch.cache.Del([]byte(key))
	if err != nil {
		return err
	}
	return ch.GormDriver.EmailDeleteSecretKey(key)
}

func (ch *ChGormDriver) NewToken(tokenID authentication.TokenID, profileID authentication.ProfileID, lifeTime authentication.TokenLifeTime) error {
	if err := ch.GormDriver.NewToken(tokenID, profileID, lifeTime); err != nil {
		return err
	}

	return ch.cache.Set([]byte(fmt.Sprint("token_", tokenID)), ch.poolInt64.Conv(int64(profileID)), int(lifeTime))
}
func (ch *ChGormDriver) DelToken(tokenID authentication.TokenID, profileID authentication.ProfileID) error {
	if err := ch.GormDriver.DelToken(tokenID, profileID); err != nil {
		return err
	}

	return ch.cache.Del([]byte(fmt.Sprint("token_", tokenID)))
}
func (ch *ChGormDriver) ReadToken(tokenID authentication.TokenID) (authentication.ProfileID, error) {
	bsKey := []byte(fmt.Sprint("token_", tokenID))
	val, exist, err := ch.cache.Get(bsKey)
	if err != nil {
		return 0, err
	}

	if exist {
		x, _ := binary.Varint(val)
		return authentication.ProfileID(x), nil
	}

	model := &GormTokenModel{}
	err = model.read(ch.db, tokenID)
	if err != nil {
		return 0, err
	}

	if model.Expiries < time.Now().Unix() {
		if err := ch.DelToken(tokenID, authentication.ProfileID(model.ProfileID)); err != nil {
			return 0, err
		}
		return 0, authentication.ErrTokenNotFound
	}

	return authentication.ProfileID(model.ProfileID), ch.cache.Set(bsKey, ch.poolInt64.Conv(model.ProfileID), int(model.Expiries-time.Now().Unix()))
}
