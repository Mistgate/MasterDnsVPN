package mgdns

import (
	"masterdnsvpn-go/internal/security"
)

// Credential is the secret of one device: an eight-byte id and a 32-byte key.
type Credential struct {
	inner security.Credential
}

// ParseCredential parses "<kid>.<key>": the kid is 16 hex characters, the key
// 64 hex characters or 43 base64url characters without padding.
func ParseCredential(secret string) (Credential, error) {
	credential, err := security.ParseCredential(secret)
	if err != nil {
		return Credential{}, err
	}
	return Credential{inner: credential}, nil
}

// ID is the kid in lower-case hex; it is the id sessions and hooks carry.
func (c Credential) ID() string { return c.inner.ID }

// CredentialIndex is an immutable set of credentials a server accepts.
type CredentialIndex struct {
	inner *security.MemoryCredentialIndex
}

// NewCredentialIndex builds an index; two credentials with the same kid are an
// error.
func NewCredentialIndex(credentials ...Credential) (*CredentialIndex, error) {
	list := make([]security.Credential, 0, len(credentials))
	for _, credential := range credentials {
		list = append(list, credential.inner)
	}
	inner, err := security.NewMemoryCredentialIndex(list)
	if err != nil {
		return nil, err
	}
	return &CredentialIndex{inner: inner}, nil
}
