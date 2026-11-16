# MasterDnsVPN fork for Mistgate

A fork of [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) (a VPN tunnel carried in DNS queries and TXT answers), based on upstream commit `b996849db0c1856024af6a00b39cd304e23dbe11`.

**The wire format of this fork is not compatible with upstream clients or servers.** Do not point an upstream client at this server or the other way round.

## What is changed and why

- **One credential per device.** Each device has an 8-byte `kid` and a 32-byte key. The server looks the device up by `kid` in an index that the embedding application can replace atomically; closing the sessions of one device does not touch another. Upstream has a single key shared by every client.
- **Authenticated encryption in both directions.** Every session frame is ChaCha20-Poly1305; nothing of the tunnel except the session id and a frame counter is readable on the wire.
- **Session setup with fresh keys.** A timestamped INIT under the device key carries an ephemeral X25519 key, the answer carries the server's, and per-direction keys are derived with HKDF-SHA256. Recording the traffic and later stealing the device key does not reveal past sessions.
- **Replay protection.** A 32-bit frame counter doubles as the AEAD nonce; each side keeps a 2048-frame replay window. A replayed frame gets an empty answer. A replayed INIT gets the identical cached answer and no second session.
- **One cipher.** The other cipher modes, the shared key file, the session cookie, the header checksum and the compression (zstd, lz4, zlib, with their dependencies) are removed.
- **Pre-session MTU probes are authenticated** with the device key, are accepted once, only while fresh, and are limited to 60 per minute per device.
- **A protocol version byte** makes a future incompatible change refuse cleanly.
- **A proper DNS server face.** Answers use a compression pointer instead of repeating the question name (the answer carries about 35 % more payload: 865 instead of about 640 bytes at an EDNS size of 1232), have their own OPT record and echo none of the query's, and a zone is an authoritative zone: an SOA, NS and A record at the apex, empty NOERROR answers inside the zone, REFUSED outside it, TC=1 and TCP 53.
- **The server cannot be used to amplify an attack.** An answer to a query that did not authenticate is never longer than the query; otherwise it is an empty answer with TC=1. Answers per source network are capped. Details and the measured numbers are in `MISTGATE.md`.
- **Embeddable.** The server takes DNS messages from its host and opens no socket; the host supplies the `Dial` and `ResolveDNS` hooks that decide where tunneled connections and DNS queries go. The client opens tunneled connections as `net.Conn` values and needs no local proxy.
- **Smaller limits by default**: 4 KiB read buffer, 1024-request queue, 64 streams per session, 64 sessions, 2 sessions per device, ARQ window 512, 20 s connect timeout, 2000 queries per second per session.

The ARQ, resolver balancing, discovery and MTU selection code is kept as upstream.

`MISTGATE.md` lists every changed file with the reason, the limits and the worst-case memory, and describes how newer upstream revisions are merged.

## Embedding: package `mgdns`

`import mgdns "masterdnsvpn-go"` (the module is `masterdnsvpn-go`, replaced by this repository in the embedding module's `go.mod`).

```go
// server side: the host owns the sockets
server, _ := mgdns.NewServer(mgdns.ServerConfig{
	Domains:    []string{"k3x9ab.t.example.com"},
	NSName:     "ns-k3x9ab.t.example.com",
	NSAddress:  netip.MustParseAddr("192.0.2.10"),
	CheckKey:   key,
	Dial:       func(ctx context.Context, credentialID, network, address string) (net.Conn, error) { ... },
	ResolveDNS: func(ctx context.Context, credentialID string, query []byte) ([]byte, error) { ... },
})
server.Start(ctx)
server.SetCredentialIndex(index) // mgdns.NewCredentialIndex(mgdns.ParseCredential("<kid>.<key>")...)
answer := server.HandleQuery(src, packet, 0, false) // UDP; true for a message read from a TCP frame
server.CloseCredential(id)       // kick
server.Sessions()                // credential, resolver address, age, counters
```

```go
// client side: no listener, no file
client, _ := mgdns.NewClient(mgdns.ClientConfig{
	Domains:     []string{"k3x9ab.t.example.com"},
	Credential:  "<kid>.<key>",
	Resolvers:   []netip.AddrPort{...}, // numbers; subnets are not expanded
	Control:     func(network, address string, c syscall.RawConn) error { ... }, // every resolver socket
	LoadRanking: ..., SaveRanking: ...,
})
client.Start(ctx)                                      // lazy: the session starts at the first dial
conn, err := client.DialContext(ctx, "tcp", "example.org:443") // the server resolves the name
answer, err := client.ResolveDNS(ctx, query)
```

There is no UDP through the tunnel: only TCP streams and DNS queries.

## Standalone use

`cmd/server` and `cmd/client` still run on their own for testing. Each reads one credential, `DEVICE_CREDENTIAL = "<16 hex kid>.<key>"`, where the key is 64 hex characters or 43 base64url characters without padding, from its config (or the `-device-credential` flag). The server also answers over TCP on the same address and port (`TCP_ENABLED`). Applications that embed the server supply the whole credential set through the credential index instead.

## Seeing the changes

```
git diff b996849d mistgate
```

## License and authorship

MIT, unchanged. The upstream copyright notice is kept in [LICENSE](LICENSE).

## Who uses it

[Mistgate](https://github.com/Mistgate/mistgate).
