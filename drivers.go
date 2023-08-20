package authentication

type DriverStorage interface {
	NewToken(tokenID TokenID, profileID ProfileID, lifeTime TokenLifeTime) error
	ReadToken(tokenID TokenID) (ProfileID, error)
	DelToken(tokenID TokenID, profileID ProfileID) error
}
