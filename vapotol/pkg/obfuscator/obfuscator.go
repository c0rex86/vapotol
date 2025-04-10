package obfuscator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

type Obfuscator struct {
	key          []byte
	encNonce     []byte
	decNonce     []byte
	
	encCounter   uint64
	decCounter   uint64
	
	encCipher    cipher.AEAD
	decCipher    cipher.AEAD
	
	minPadding   int
	maxPadding   int
	
	mu           sync.Mutex
	
	method       byte
}

func New() *Obfuscator {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		h := sha256.New()
		h.Write([]byte(time.Now().String()))
		key = h.Sum(nil)
	}
	
	encNonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, encNonce); err != nil {
		binary.BigEndian.PutUint64(encNonce, uint64(time.Now().UnixNano()))
	}
	
	decNonce := make([]byte, 12)
	copy(decNonce, encNonce)
	
	return &Obfuscator{
		key:        key,
		encNonce:   encNonce,
		decNonce:   decNonce,
		encCounter: 0,
		decCounter: 0,
		minPadding: 8,
		maxPadding: 32,
		method:     1,
	}
}

func (o *Obfuscator) WithKey(key []byte) *Obfuscator {
	o.mu.Lock()
	defer o.mu.Unlock()
	
	h := sha256.New()
	h.Write(key)
	o.key = h.Sum(nil)
	
	o.encCounter = 0
	o.decCounter = 0
	o.encCipher = nil
	o.decCipher = nil
	
	return o
}

func (o *Obfuscator) WithMethod(method byte) *Obfuscator {
	o.mu.Lock()
	defer o.mu.Unlock()
	
	if method > 2 {
		method = 1
	}
	
	o.method = method
	return o
}

func (o *Obfuscator) WithPadding(min, max int) *Obfuscator {
	o.mu.Lock()
	defer o.mu.Unlock()
	
	if min < 0 {
		min = 0
	}
	
	if max < min {
		max = min
	}
	
	if max > 256 {
		max = 256
	}
	
	o.minPadding = min
	o.maxPadding = max
	
	return o
}

func (o *Obfuscator) Obfuscate(data []byte) []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	
	method := o.method
	
	switch method {
	case 0:
		return o.obfuscateXOR(data)
	case 1:
		return o.obfuscateAESGCM(data)
	case 2:
		return o.obfuscateScramble(data)
	default:
		return o.obfuscateAESGCM(data)
	}
}

func (o *Obfuscator) Deobfuscate(data []byte) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	
	if len(data) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	
	method := data[0]
	
	switch method {
	case 0:
		return o.deobfuscateXOR(data[1:])
	case 1:
		return o.deobfuscateAESGCM(data[1:])
	case 2:
		return o.deobfuscateScramble(data[1:])
	default:
		return o.deobfuscateAESGCM(data[1:])
	}
}

func (o *Obfuscator) obfuscateXOR(data []byte) []byte {
	paddingLen := o.minPadding
	if o.maxPadding > o.minPadding {
		paddingLen += int(time.Now().UnixNano() % int64(o.maxPadding-o.minPadding))
	}
	
	result := make([]byte, 1+1+paddingLen+len(data))
	
	result[0] = 0
	
	result[1] = byte(paddingLen)
	
	if paddingLen > 0 {
		if _, err := io.ReadFull(rand.Reader, result[2:2+paddingLen]); err != nil {
			for i := 0; i < paddingLen; i++ {
				result[2+i] = byte(i)
			}
		}
	}
	
	copy(result[2+paddingLen:], data)
	
	keyIndex := 0
	for i := 1; i < len(result); i++ {
		result[i] ^= o.key[keyIndex]
		keyIndex = (keyIndex + 1) % len(o.key)
	}
	
	return result
}

func (o *Obfuscator) deobfuscateXOR(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, io.ErrUnexpectedEOF
	}
	
	buf := make([]byte, len(data))
	copy(buf, data)
	
	keyIndex := 0
	for i := 0; i < len(buf); i++ {
		buf[i] ^= o.key[keyIndex]
		keyIndex = (keyIndex + 1) % len(o.key)
	}
	
	paddingLen := int(buf[0])
	if len(buf) < 1+paddingLen {
		return nil, io.ErrUnexpectedEOF
	}
	
	return buf[1+paddingLen:], nil
}

func (o *Obfuscator) obfuscateAESGCM(data []byte) []byte {
	if o.encCipher == nil {
		block, err := aes.NewCipher(o.key)
		if err != nil {
			result := make([]byte, 1+len(data))
			result[0] = 1
			copy(result[1:], data)
			return result
		}
		
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			result := make([]byte, 1+len(data))
			result[0] = 1
			copy(result[1:], data)
			return result
		}
		
		o.encCipher = aesGCM
	}
}