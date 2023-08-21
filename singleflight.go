package authentication

import (
	"fmt"

	"golang.org/x/sync/singleflight"
)

func RunSingleflightDriverStorage(st DriverStorage) DriverStorage {
	sing := new(SingleflightDriverStorage)
	sing.st = st
	return sing
}

type SingleflightDriverStorage struct {
	req singleflight.Group
	st  DriverStorage
}

func (sing *SingleflightDriverStorage) EmailNewSecretKey(key EmailSecretKey, email string, lifetime int64) error {
	return sing.st.EmailNewSecretKey(key, email, lifetime)

}
func (sing *SingleflightDriverStorage) EmailReadSecretKey(key EmailSecretKey) (email string, err error) {
	v, err, _ := sing.req.Do(string(key), func() (interface{}, error) {
		return sing.st.EmailReadSecretKey(key)
	})

	return v.(string), err
}

func (sing *SingleflightDriverStorage) EmailDeleteSecretKey(key EmailSecretKey) error {
	return sing.st.EmailDeleteSecretKey(key)
}

func (sing *SingleflightDriverStorage) NewToken(tokenID TokenID, profileID ProfileID, lifeTime TokenLifeTime) error {
	return sing.st.NewToken(tokenID, profileID, lifeTime)
}

func (sing *SingleflightDriverStorage) ReadToken(tokenID TokenID) (ProfileID, error) {
	v, err, _ := sing.req.Do(string(tokenID), func() (interface{}, error) {
		return sing.st.ReadToken(tokenID)
	})
	return v.(ProfileID), err
}

func (sing *SingleflightDriverStorage) DelToken(tokenID TokenID, profileID ProfileID) error {
	return sing.st.DelToken(tokenID, profileID)
}

func (sing *SingleflightDriverStorage) IsUniqueLogin(login string) (bool, error) {
	v, err, _ := sing.req.Do("1"+string(login), func() (interface{}, error) {
		return sing.st.IsUniqueLogin(login)
	})
	return v.(bool), err
}
func (sing *SingleflightDriverStorage) IsUniqueEmail(email string) (bool, error) {
	v, err, _ := sing.req.Do("2"+string(email), func() (interface{}, error) {
		return sing.st.IsUniqueEmail(email)
	})
	return v.(bool), err
}

func (sing *SingleflightDriverStorage) NewProfile(login, email, password string) (ProfileID, error) {
	return sing.st.NewProfile(login, email, password)
}
func (sing *SingleflightDriverStorage) DelProfile(profileID ProfileID) error {
	return sing.st.DelProfile(profileID)
}

func (sing *SingleflightDriverStorage) SetPasswordProfileByEmail(email string, password string) error {
	return sing.st.SetPasswordProfileByEmail(email, password)
}
func (sing *SingleflightDriverStorage) SetPasswordProfileByProfileID(profileID ProfileID, password string) error {
	return sing.st.SetPasswordProfileByProfileID(profileID, password)
}
func (sing *SingleflightDriverStorage) SetEmailByProfileID(profileID ProfileID, email string) error {
	return sing.st.SetEmailByProfileID(profileID, email)
}

func (sing *SingleflightDriverStorage) GetProfileIDByEmail(email string) (profileID ProfileID, err error) {
	v, err, _ := sing.req.Do("3"+string(email), func() (interface{}, error) {
		return sing.st.GetProfileIDByEmail(email)
	})
	return v.(ProfileID), err
}
func (sing *SingleflightDriverStorage) GetPasswordByID(profileID ProfileID) (password string, err error) {
	v, err, _ := sing.req.Do(fmt.Sprint("4", profileID), func() (interface{}, error) {
		return sing.st.GetPasswordByID(profileID)
	})
	return v.(string), err
}

func (sing *SingleflightDriverStorage) GetPasswordByLogin(login string) (res *ResultPasswordByLogin, err error) {
	v, err, _ := sing.req.Do("5"+string(login), func() (interface{}, error) {
		return sing.st.GetPasswordByLogin(login)
	})
	return v.(*ResultPasswordByLogin), err
}
func (sing *SingleflightDriverStorage) GetLoginByEmail(email string) (login string, err error) {
	v, err, _ := sing.req.Do("6"+string(email), func() (interface{}, error) {
		return sing.st.GetLoginByEmail(email)
	})
	return v.(string), err
}

func (sing *SingleflightDriverStorage) GetEmail(profileID ProfileID) (email string, err error) {
	v, err, _ := sing.req.Do(fmt.Sprint("7", profileID), func() (interface{}, error) {
		return sing.st.GetEmail(profileID)
	})
	return v.(string), err
}

func (sing *SingleflightDriverStorage) GetLogin(profileID ProfileID) (login string, err error) {
	v, err, _ := sing.req.Do(fmt.Sprint("8", profileID), func() (interface{}, error) {
		return sing.st.GetLogin(profileID)
	})
	return v.(string), err
}
