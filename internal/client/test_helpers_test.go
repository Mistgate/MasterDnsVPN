package client

import (
	"testing"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/udpserver"
)

const testDeviceCredential = "0102030405060708.0000000000000000000000000000000000000000000000000000000000000000"

func clientTestCredential() security.Credential {
	credential, err := security.ParseCredential(testDeviceCredential)
	if err != nil {
		panic(err)
	}
	return credential
}

func clientTestUDPServer(cfg config.ServerConfig, log *logger.Logger) *udpserver.Server {
	index, err := security.NewMemoryCredentialIndex([]security.Credential{clientTestCredential()})
	if err != nil {
		panic(err)
	}
	server := udpserver.New(cfg, log)
	server.SetCredentialIndex(index)
	return server
}

func buildTestClientWithResolvers(cfg config.ClientConfig, keys ...string) *Client {
	cfg.AutoSaveRankedResolvers = false
	c := New(cfg, nil, clientTestCredential())
	c.active_streams = make(map[uint16]*Stream_client)

	connections := make([]Connection, 0, len(keys))
	ptrs := make([]*Connection, 0, len(keys))
	for i, key := range keys {
		conn := Connection{
			Key:           key,
			Domain:        key + ".example.com",
			Resolver:      "127.0.0.1",
			ResolverPort:  5300 + i,
			ResolverLabel: "127.0.0.1:" + string(rune('0'+i)),
		}
		connections = append(connections, conn)
	}
	for i := range connections {
		ptrs = append(ptrs, &connections[i])
	}
	c.balancer.SetConnections(ptrs)
	for _, key := range keys {
		c.balancer.SetConnectionMTU(key, 120, 180, 220)
		c.balancer.SetConnectionValidity(key, true)
	}
	return c
}

func waitForResolverHealthCondition(t *testing.T, timeout time.Duration, cond func() bool, message string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	if cond() {
		return
	}
	t.Fatal(message)
}
