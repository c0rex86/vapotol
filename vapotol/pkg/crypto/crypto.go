package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

type Cryptor struct {
	key       []byte
	salt      []byte
	encNonce  []byte
	decNonce  []byte
	encCount  uint64
	decCount  uint64
	encCipher cipher.AEAD
	decCipher cipher.AEAD
	mu        sync.Mutex
}

func New() (*Cryptor, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		h := sha256.New()
		h.Write([]byte(time.Now().String()))
		key = h.Sum(nil)
	}
	
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		h := sha256.New()
		h.Write(key)
		copy(salt, h.Sum(nil)[:16])
	}
	
	return NewWithKey(key, salt)
}

func NewWithKey(key, salt []byte) (*Cryptor, error) {
	if len(key) < 16 {
		return nil, errors.New("ключ слишком короткий, минимум 16 байт")
	}
	
	if len(key) > 32 {
		key = key[:32]
	} else if len(key) < 32 {
		h := sha256.New()
		h.Write(key)
		key = h.Sum(nil)
	}
	
	if len(salt) > 16 {
		salt = salt[:16]
	} else if len(salt) < 16 {
		newSalt := make([]byte, 16)
		copy(newSalt, salt)
		salt = newSalt
	}
	
	encNonce := make([]byte, 12)
	decNonce := make([]byte, 12)
	
	copy(encNonce, salt[:12])
	copy(decNonce, salt[:12])
	
	return &Cryptor{
		key:      key,
		salt:     salt,
		encNonce: encNonce,
		decNonce: decNonce,
		encCount: 0,
		decCount: 0,
	}, nil
}

func (c *Cryptor) Encrypt(plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.encCipher == nil {
		block, err := aes.NewCipher(c.key)
		if err != nil {
			return nil, err
		}
		
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		
		c.encCipher = aesGCM
	}
	
	nonce := make([]byte, 12)
	copy(nonce, c.encNonce)
	
	binary.BigEndian.PutUint64(nonce[4:], c.encCount)
	c.encCount++
	
	ciphertext := c.encCipher.Seal(nil, nonce, plaintext, nil)
	
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)
	
	return result, nil
}

func (c *Cryptor) Decrypt(data []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if len(data) < 12 {
		return nil, errors.New("данные слишком короткие")
	}
	
	if c.decCipher == nil {
		block, err := aes.NewCipher(c.key)
		if err != nil {
			return nil, err
		}
		
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		
		c.decCipher = aesGCM
	}
	
	nonce := data[:12]
	ciphertext := data[12:]
	
	plaintext, err := c.decCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

func (c *Cryptor) ChangeKey(newKey []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if len(newKey) < 16 {
		return errors.New("ключ слишком короткий, минимум 16 байт")
	}
	
	if len(newKey) > 32 {
		newKey = newKey[:32]
	} else if len(newKey) < 32 {
		h := sha256.New()
		h.Write(newKey)
		newKey = h.Sum(nil)
	}
	
	c.key = newKey
	c.encCipher = nil
	c.decCipher = nil
	
	c.encCount = 0
	c.decCount = 0
	
	return nil
}

func (c *Cryptor) GetEncryptionKey() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	keyCopy := make([]byte, len(c.key))
	copy(keyCopy, c.key)
	
	return keyCopy
}

func (c *Cryptor) GetSalt() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	saltCopy := make([]byte, len(c.salt))
	copy(saltCopy, c.salt)
	
	return saltCopy
}

func (c *Cryptor) HashPassword(password []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	h := sha256.New()
	h.Write(password)
	h.Write(c.salt)
	
	return h.Sum(nil)
}
