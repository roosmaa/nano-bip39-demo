package main

import (
	"errors"
	"golang.org/x/crypto/blake2b"
)

var (
	ErrInvalidPublicKey = errors.New("nano: invalid public key")
)

var base32Alphabet = [32]byte{
	'1', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
	'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
	'r', 's', 't', 'u', 'w', 'x', 'y', 'z'}

// Define some binary "literals" for the massive bit manipulation operation
// when converting public key to account string.
const (
	b11111 = 31
	b01111 = 15
	b00111 = 7
	b00011 = 3
	b00001 = 1
)

type encodeAddressBuf struct {
	check     []byte
	publicKey []byte
}

func (b *encodeAddressBuf) GetByte(i int) byte {
	if i < len(b.check) {
		return b.check[i]
	} else if i-len(b.check) < len(b.publicKey) {
		return b.publicKey[len(b.publicKey)-1-(i-len(b.check))]
	}
	return 0
}

func EncodeAddress(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", ErrInvalidPublicKey
	}

	h, err := blake2b.New(5, nil)
	if err != nil {
		return "", err
	}
	h.Write(publicKey)
	check := h.Sum(nil)

	raw := make([]byte, 60)
	buf := encodeAddressBuf{
		check:     check,
		publicKey: publicKey,
	}
	for k := 0; k < len(raw); k++ {
		i := (k / 8) * 5

		var c byte
		switch k % 8 {
		case 0:
			c = buf.GetByte(i) & b11111
		case 1:
			c = (buf.GetByte(i) >> 5) & b00111
			c |= (buf.GetByte(i+1) & b00011) << 3
		case 2:
			c = (buf.GetByte(i+1) >> 2) & b11111
		case 3:
			c = (buf.GetByte(i+1) >> 7) & b00001
			c |= (buf.GetByte(i+2) & b01111) << 1
		case 4:
			c = (buf.GetByte(i+2) >> 4) & b01111
			c |= (buf.GetByte(i+3) & b00001) << 4
		case 5:
			c = (buf.GetByte(i+3) >> 1) & b11111
		case 6:
			c = (buf.GetByte(i+3) >> 6) & b00011
			c |= (buf.GetByte(i+4) & b00111) << 2
		case 7:
			c = (buf.GetByte(i+4) >> 3) & b11111
		}
		raw[len(raw)-1-k] = base32Alphabet[c]
	}

	return "nano_" + string(raw), nil
}
