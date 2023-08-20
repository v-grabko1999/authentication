package authentication

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"sync"
)

type poolHASH struct {
	p *sync.Pool
}

func newPoolHash() *poolHASH {
	return &poolHASH{
		p: &sync.Pool{
			New: func() any {
				return sha256.New()
			},
		},
	}
}

func (p *poolHASH) Get() hash.Hash {
	raw := p.p.Get().(hash.Hash)
	return raw
}

func (p *poolHASH) Put(b hash.Hash) {
	b.Reset()
	p.p.Put(b)
}

type lifeTimeToBytes struct {
	p *sync.Pool
}

type PoolBytesRaw struct {
	BS []byte
}

func newPoolLifeTime() *lifeTimeToBytes {
	return &lifeTimeToBytes{
		p: &sync.Pool{
			New: func() any {
				return &PoolBytesRaw{make([]byte, binary.MaxVarintLen64)}
			},
		},
	}
}

func (p *lifeTimeToBytes) Conv(i TokenLifeTime) []byte {
	buf := p.p.Get().(*PoolBytesRaw)
	defer func() {
		buf.BS = buf.BS[:0]
		p.p.Put(buf)
	}()
	return buf.BS[:binary.PutVarint(buf.BS, int64(i))]
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

type profilePasswordSaltTranz struct {
	bs []byte
	s  sync.RWMutex
}

func (p *profilePasswordSaltTranz) Hash(login, password string) string {
	p.s.RLock()
	defer p.s.RUnlock()
	return signature(p.bs, []byte(login), p.bs, []byte(password))
}
