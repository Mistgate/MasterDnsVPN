# Mistgate fork notes

## Base

Upstream MasterDnsVPN commit `b996849db0c1856024af6a00b39cd304e23dbe11` ("Remove MD files", 2026-11-14). The same value is the `Version` constant of the `mgdns` package. The Go module line (`module masterdnsvpn-go`) is unchanged so that upstream merges without rewriting imports.

The wire format of this fork is owned here and is not compatible with upstream (protocol version byte `1`).

## Wire format, version 1

All integers are big endian. `kid` is 8 bytes, the device key `psk` is 32 bytes. AEAD is ChaCha20-Poly1305 with a 16-byte tag.

| Message | Layout |
| --- | --- |
| INIT (71 bytes) | `ver 1 \| kid 8 \| ts 4 \| e_c 32 \| AEAD_psk(10 parameter bytes)`; AAD = the first 45 bytes; nonce = first 12 bytes of SHA-256(`"masterdnsvpn-go/init/v1"` \|\| header) |
| ACCEPT | `e_s 32 \| AEAD_psk(sid 1 \| policy)`; AAD = `"masterdnsvpn-go/accept-aad/v1"` \|\| INIT \|\| e_s; nonce = first 12 bytes of SHA-256(`"masterdnsvpn-go/accept/v1"` \|\| INIT \|\| e_s) |
| Session keys | HKDF-SHA256(ikm = psk \|\| X25519(e_c, e_s), salt = SHA-256(INIT \|\| ACCEPT), info = `"masterdnsvpn-go v1 client-to-server"` or `"... server-to-client"`), 32 bytes each |
| Frame (both directions) | `sid 1 \| ctr 4 \| AEAD_dirkey(inner packet)`; nonce = 8 zero bytes \|\| ctr; AAD = `ver 1 \| sid \| ctr` |
| Pre-session probe and its answer | `ver 1 \| kind 0x50 \| kid 8 \| nonce 12 (ts 4 \| random 8) \| AEAD_psk(inner packet)`; AAD = header |
| Inner packet | `type 1 \|` the stream, sequence, fragment and compression fields that the type carries `\| payload` (8 header bytes for STREAM_DATA, 1 for PING) |

A server accepts an INIT or probe whose timestamp is within 120 seconds of its clock. A repeated identical INIT within that time returns the cached ACCEPT (at most 16 times per INIT); the server never builds a second ACCEPT or session for one INIT. The frame counter starts at 0 for each direction and each session, a receiver keeps a 2048-frame replay window, the client ends the session after 2^31 frames in a direction, and the cipher refuses to seal after 2^32 - 1 (then the silent downlink ends the session from the other side).

## Behaviour that follows from this

- The server never answers an INIT that is unknown, stale, wrongly keyed or malformed, nor a replayed INIT whose cached ACCEPT has been dropped. Frames for unknown sessions and replayed frames get an ordinary empty DNS answer (no data).
- The server has no key to sign a "session lost" message with, so the client treats 90 seconds without any authenticated downlink frame as a lost session and starts a new one. The old unauthenticated ERROR_DROP and SESSION_BUSY answers are no longer sent.
- A pre-session probe is answered once, only while fresh, at most 60 times a minute per device.
- The upload MTU found by probing is the payload a session frame can carry in the same name: the probe is shortened by the difference between the probe envelope and the frame overhead (`uploadProbeSlack`).

## Changed files

| File | Reason |
| --- | --- |
| `mgdns.go` | Empty public facade package and the upstream base `Version`. |
| `README.MD`; `README_ES/FA/IT/RU/ZH.MD` removed | Describe this fork; the translations described upstream. |
| `MISTGATE.md` | This file. |
| `internal/security/protocol.go` | Credentials and the atomic credential index, INIT/ACCEPT, key schedule, directional frame AEAD, replay window, probes and probe limiter. |
| `internal/security/codec.go`, `encryption_key.go` (removed) | Cipher methods 0-5 and the shared `ENCRYPTION_KEY` / `encrypt_key.txt`. |
| `internal/vpnproto/builder.go`, `parser.go`, `payload.go` | The inner packet no longer has a session id, cookie or header check; no codec in the parser. |
| `internal/vpnproto/session_accept.go` | The ACCEPT policy block without the clear session id and cookie. |
| `internal/dnsparser/transport.go` | Opaque response payload (the downlink is ciphertext), TXT chunking over the whole frame. |
| `internal/udpserver/server_protocol.go` | Demultiplexing of frames, INIT and probes; INIT cache; probe answers. |
| `internal/udpserver/server.go`, `server_ingress.go`, `server_session.go`, `server_postsession.go`, `server_deferred.go`, `server_runtime.go`, `session.go` | Credential index in the server, per-session cipher, sealed downlink, removal of the session cookie and of the invalid-cookie tracker (`invalid_cookie_tracker.go` removed). |
| `internal/client/client.go`, `session.go`, `async_runtime.go`, `tunnel_query.go`, `tunnel_runtime.go`, `dispatcher.go`, `handlers/packed_control_handler.go` | Handshake, a fresh counter for every copy of a duplicated packet, sealed uplink and downlink, INIT rebuilt before it goes stale, silent-downlink and counter-limit session restart. |
| `internal/client/mtu.go`, `micro_burst.go` | Authenticated probes and the probe/frame size compensation; discovery and selection logic is as upstream. |
| `internal/client/client_utils.go` | Banner no longer prints a cipher number. |
| `internal/config/client.go`, `server.go` | `DEVICE_CREDENTIAL` replaces `DATA_ENCRYPTION_METHOD`, `ENCRYPTION_KEY`, `ENCRYPTION_KEY_FILE`; the `INVALID_COOKIE_*` settings are gone. |
| `client_config.toml.simple`, `server_config.toml.simple` | The same settings in the sample configs. |
| `cmd/client/main.go`, `cmd/server/main.go` | One standalone credential; no `-genkey`. |
| `docker/entrypoint/*`, `docker/smoke-test.sh`, `server_linux_install.sh`, `scripts/bench/bench.go`, `.github/workflows/build-go.yml`, `build-test.yml` | No key generation or key file; they use a credential. |

Tests: new `internal/security/protocol_test.go` (with an independent reference in `reference_test.go`), `internal/udpserver/server_protocol_test.go`, `server_protocol_replay_test.go`, `e2e_test.go`, `internal/client/session_liveness_test.go`. Upstream tests were changed only to build clients and servers with a credential, to drop the cookie, and where the format changed (the list is in the commit messages).

## Merging newer upstream revisions

Merge, do not rebase: `git fetch upstream && git merge upstream/main` on the `mistgate` branch.

- `internal/vpnproto`, `internal/security` and `internal/dnsparser` define the wire format. Resolve conflicts there in favour of this fork; upstream changes in those packages are not taken (port a fix by hand if it is independent of the format).
- `internal/arq`, the balancer, resolver discovery and MTU selection are kept as upstream so that merging them stays easy. The only fork changes near them are the probe envelope and size accounting in `internal/client/mtu.go` and `micro_burst.go`; keep those when merging selection or discovery fixes.
- After a merge run `go vet ./...`, `go test ./...` and, for the protocol, `go test -run 'Pinned|Reference' ./internal/security`: the pinned vectors must not change.
