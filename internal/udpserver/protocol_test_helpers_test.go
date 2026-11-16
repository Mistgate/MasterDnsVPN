package udpserver

import (
	"crypto/rand"
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
)

const testDeviceCredential = "0102030405060708.0000000000000000000000000000000000000000000000000000000000000000"

func protocolTestCredential(t testing.TB) security.Credential {
	t.Helper()
	credential, err := security.ParseCredential(testDeviceCredential)
	if err != nil {
		t.Fatalf("ParseCredential failed: %v", err)
	}
	return credential
}

func newProtocolTestServer(t testing.TB, cfg config.ServerConfig, log *logger.Logger) (*Server, security.Credential) {
	t.Helper()
	credential := protocolTestCredential(t)
	index, err := security.NewMemoryCredentialIndex([]security.Credential{credential})
	if err != nil {
		t.Fatalf("NewMemoryCredentialIndex failed: %v", err)
	}
	server := New(cfg, log)
	server.SetCredentialIndex(index)
	return server, credential
}

func makeProtocolTestInit(t testing.TB, credential security.Credential, parameters [security.InitParametersSize]byte) (*security.ClientHandshake, []byte) {
	t.Helper()
	handshake, message, err := security.NewClientHandshake(credential, parameters, time.Now(), rand.Reader)
	if err != nil {
		t.Fatalf("NewClientHandshake failed: %v", err)
	}
	return handshake, message
}

// callSecureInit runs the INIT handler the way the packet path does: the INIT
// is authenticated first, the handler only ever sees an authenticated INIT.
func callSecureInit(s *Server, query []byte, requestName string, message []byte) []byte {
	credential, init, err := security.OpenSessionInit(message, s.credentialIndex, time.Now())
	if err != nil {
		return nil
	}
	return s.handleSecureSessionInit(query, requestName, credential, init, message)
}
