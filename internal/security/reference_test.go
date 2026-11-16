package security

// This file is an independent, deliberately small re-derivation of the v1
// byte layouts from the specification. It uses only the standard library and
// golang.org/x/crypto and never calls the functions under test, so a field-order
// or nonce/AAD mistake in protocol.go cannot also hide in the expected bytes.

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func refPublic(private []byte) []byte {
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return public
}

func refSeal(key, nonce, plaintext, aad []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, nonce, plaintext, aad)
}

func refHash12(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)[:12]
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// refInit: ver 1 | kid 8 | ts 4 | e_c 32 | AEAD_psk(params), AAD = the first 45 bytes,
// nonce = first 12 bytes of SHA-256("masterdnsvpn-go/init/v1" || header).
func refInit(kid, psk []byte, ts uint32, clientPrivate, params []byte) []byte {
	header := cat([]byte{1}, kid, be32(ts), refPublic(clientPrivate))
	nonce := refHash12([]byte("masterdnsvpn-go/init/v1"), header)
	return cat(header, refSeal(psk, nonce, params, header))
}

// refAccept: e_s 32 | AEAD_psk(sid || policy); returns the message and both
// directional keys derived by HKDF-SHA256(ikm = psk || X25519, salt = SHA-256(init || accept)).
func refAccept(psk, initMessage, clientPrivate, serverPrivate []byte, sid byte, policy []byte) (accept, c2s, s2c []byte) {
	serverPublic := refPublic(serverPrivate)
	nonce := refHash12([]byte("masterdnsvpn-go/accept/v1"), initMessage, serverPublic)
	aad := cat([]byte("masterdnsvpn-go/accept-aad/v1"), initMessage, serverPublic)
	accept = cat(serverPublic, refSeal(psk, nonce, cat([]byte{sid}, policy), aad))

	shared, err := curve25519.X25519(serverPrivate, refPublic(clientPrivate))
	if err != nil {
		panic(err)
	}
	salt := sha256.Sum256(cat(initMessage, accept))
	derive := func(info string) []byte {
		out := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha256.New, cat(psk, shared), salt[:], []byte(info)), out); err != nil {
			panic(err)
		}
		return out
	}
	return accept, derive("masterdnsvpn-go v1 client-to-server"), derive("masterdnsvpn-go v1 server-to-client")
}

// refFrame: sid 1 | ctr 4 | AEAD(plaintext), nonce = 8 zero bytes || ctr,
// AAD = version 1 || sid || ctr.
func refFrame(key []byte, sid byte, counter uint32, plaintext []byte) []byte {
	prefix := cat([]byte{sid}, be32(counter))
	nonce := cat(make([]byte, 8), be32(counter))
	return cat(prefix, refSeal(key, nonce, plaintext, cat([]byte{1}, prefix)))
}

// refProbe: ver 1 | kind 0x50 | kid 8 | nonce 12 (ts 4 || random 8) | AEAD_psk(payload), AAD = header.
func refProbe(kid, psk []byte, ts uint32, random8 []byte, payload []byte) []byte {
	header := cat([]byte{1, 0x50}, kid, be32(ts), random8)
	return cat(header, refSeal(psk, header[10:22], payload, header))
}
