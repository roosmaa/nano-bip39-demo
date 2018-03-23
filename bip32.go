package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const Hardened = uint32(0x80000000)

type Bip32Path []uint32

func (p Bip32Path) String() string {
	arr := make([]string, len(p))
	for i, childIdx := range p {
		if childIdx >= 0x80000000 {
			arr[i] = fmt.Sprintf("%d'", childIdx-0x80000000)
		} else {
			arr[i] = fmt.Sprintf("%d", childIdx)
		}

	}
	return strings.Join(arr, "/")
}

type Bip32 struct {
	Key       []byte
	ChainCode []byte
}

// Derive private key from seed for Ed25519 curve using the algorithm
// defined in SLIP-0010.
// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
func DerivePrivateKey(seed []byte, path Bip32Path) (*Bip32, error) {
	b := &Bip32{}

	digest := hmac.New(sha512.New, []byte("ed25519 seed"))
	_, err := digest.Write(seed)
	if err != nil {
		return nil, err
	}
	intermediary := digest.Sum(nil)
	b.Key = intermediary[:32]
	b.ChainCode = intermediary[32:]

	// Derive the requested path
	for _, childIdx := range path {
		if childIdx < Hardened {
			return nil, errors.New("bip32: only hardened keys supported for Ed25519")
		}

		data := make([]byte, 1+32+4)
		data[0] = 0x00
		copy(data[1:1+32], b.Key)
		binary.BigEndian.PutUint32(data[1+32:1+32+4], childIdx)

		digest = hmac.New(sha512.New, b.ChainCode)
		_, err = digest.Write(data)
		if err != nil {
			return nil, err
		}
		intermediary = digest.Sum(nil)
		b.Key = intermediary[:32]
		b.ChainCode = intermediary[32:]
	}

	return b, nil
}
