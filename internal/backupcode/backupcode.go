package backupcode

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

const Alphabet = "23456789ABCDEFGHJKMNPQRSTWXYZ"

const TTL = 10 * time.Minute

const Attempts = 5

var (
	ErrNoCode = errors.New("код не выдан или больше не действует — получите новый код на экране шлюза")

	ErrWrongCode = errors.New("код не совпал")
)

type Store struct {
	mu      sync.Mutex
	sum     [32]byte
	expires time.Time
	left    int
	now     func() time.Time
}

func New() *Store { return &Store{now: time.Now} }

func (s *Store) Issue() (string, error) {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		if i == 4 {
			b.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(Alphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(Alphabet[n.Int64()])
	}
	code := b.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sum = sha256.Sum256([]byte(code))
	s.expires = s.now().Add(TTL)
	s.left = Attempts
	return code, nil
}

func (s *Store) Use(raw string) error {
	sum := sha256.Sum256([]byte(Normalize(raw)))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.left <= 0 || !s.now().Before(s.expires) {
		s.left = 0
		return ErrNoCode
	}
	if subtle.ConstantTimeCompare(sum[:], s.sum[:]) == 1 {
		s.left = 0
		return nil
	}
	s.left--
	if s.left == 0 {
		return ErrNoCode
	}
	return fmt.Errorf("%w: осталось попыток — %d", ErrWrongCode, s.left)
}

func Normalize(raw string) string {
	up := strings.ToUpper(strings.Join(strings.Fields(raw), ""))
	up = strings.ReplaceAll(up, "-", "")
	if len(up) == 8 {
		return up[:4] + "-" + up[4:]
	}
	return up
}
