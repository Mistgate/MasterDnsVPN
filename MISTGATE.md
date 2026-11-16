# Mistgate fork notes

## Base

Upstream MasterDnsVPN commit `b996849db0c1856024af6a00b39cd304e23dbe11` ("Remove MD files", 2026-11-14). The same value is the `Version` constant of the `mgdns` package. The Go module line (`module masterdnsvpn-go`) is unchanged so that upstream merges without rewriting imports.

The wire format of this fork is owned here and is not compatible with upstream (protocol version byte `1`).

## Wire format, version 1

All integers are big endian. `kid` is 8 bytes, the device key `psk` is 32 bytes. AEAD is ChaCha20-Poly1305 with a 16-byte tag.

| Message | Layout |
| --- | --- |
| INIT (70 bytes) | `ver 1 \| kid 8 \| ts 4 \| e_c 32 \| AEAD_psk(9 parameter bytes)`; AAD = the first 45 bytes; nonce = first 12 bytes of SHA-256(`"masterdnsvpn-go/init/v1"` \|\| header). The parameters are response mode 1, upload MTU 2, download MTU 2, verify code 4. |
| ACCEPT | `e_s 32 \| AEAD_psk(sid 1 \| verify code 4 \| policy 11)`; AAD = `"masterdnsvpn-go/accept-aad/v1"` \|\| INIT \|\| e_s; nonce = first 12 bytes of SHA-256(`"masterdnsvpn-go/accept/v1"` \|\| INIT \|\| e_s) |
| Session keys | HKDF-SHA256(ikm = psk \|\| X25519(e_c, e_s), salt = SHA-256(INIT \|\| ACCEPT), info = `"masterdnsvpn-go v1 client-to-server"` or `"... server-to-client"`), 32 bytes each |
| Frame (both directions) | `sid 1 \| ctr 4 \| AEAD_dirkey(inner packet)`; nonce = 8 zero bytes \|\| ctr; AAD = `ver 1 \| sid \| ctr` |
| Pre-session probe and its answer | `ver 1 \| kind 0x50 \| kid 8 \| nonce 12 (ts 4 \| random 8) \| AEAD_psk(inner packet)`; AAD = header |
| Inner packet | `type 1 \|` the stream, sequence and fragment fields that the type carries `\| payload` (7 header bytes for STREAM_DATA, 1 for PING) |

A server accepts an INIT or probe whose timestamp is within 120 seconds of its clock. A repeated identical INIT within that time returns the cached ACCEPT (at most 9 times over UDP and 16 over TCP per INIT); the server never builds a second ACCEPT or session for one INIT. The frame counter starts at 0 for each direction and each session, a receiver keeps a 2048-frame replay window, the client ends the session after 2^31 frames in a direction, and the cipher refuses to seal after 2^32 - 1 (then the silent downlink ends the session from the other side).

There is no compression: the compression byte of the inner packet, the compression pair of INIT and ACCEPT, and the `zstd`, `lz4` and `zlib` code with its two dependencies are gone.

## The DNS envelope

| | Upstream | This fork |
| --- | --- | --- |
| Owner of an answer record | the question name copied in full | compression pointer `0xC00C` |
| OPT record of an answer | the query's OPT echoed (a client cookie too) | our own, empty, UDP size 1232; none when the query had none |
| Flags of a tunnel or zone answer | RA=1, AA=0 | RA=0, AA=1 |
| Name outside every zone | NXDOMAIN with AA | REFUSED, no AA |
| Size | never truncated | at most the EDNS size of the query (512 without OPT); too long: empty answer with TC=1 |
| DNS message ID of a query | a counter | random |

### Zone responder

For each name in `DOMAIN` the server is a minimal authoritative server: no zone file, no external daemon.

| Query | Answer |
| --- | --- |
| apex SOA | SOA: mname = `ZONE_NS_NAME`, rname = `hostmaster.<zone>`, serial 1, refresh 3600, retry 600, expire 86400, minimum 60 |
| apex NS | `ZONE_NS_NAME` (when set) |
| apex A | `ZONE_A_ADDRESS` (when set) |
| other types at the apex, ANY | NOERROR, no data, SOA in the authority section |
| a name inside the zone that is not a tunnel query (`x.<zone>` for QNAME minimisation, a non-TXT type, a TXT label shorter than `MIN_VPN_LABEL_LENGTH`) | NOERROR, no data - never NXDOMAIN, which would cut off every name below |
| `_mgchk-<nonce>.<zone>` TXT, nonce 8 to 32 characters of `[a-z0-9]` | `hex(HMAC-SHA256(ZONE_CHECK_KEY, nonce))`; proves that a query reached this node |
| AXFR, IXFR | REFUSED |
| opcode other than QUERY | NOTIMP |
| more or fewer than one question | FORMERR |
| a tunnel TXT query | handled by the tunnel |

The SOA goes into the authority section of a no-data answer only when that does not make the answer longer than the query.

### No amplification (`HandleQuery`)

Rules, in the order they apply:

1. A UDP answer is never longer than the EDNS size of the query (512 bytes when it has no OPT record) and never longer than `maxResp`, the limit of the host's transport.
2. An answer to a query that did **not authenticate** is never longer than the query in bytes. A query authenticates when an AEAD tag, a key-bound INIT or a key-bound probe verified. Everything else - a name outside the zones, the apex, ANY, a garbage frame, an unknown device, a replayed frame or probe, a probe without the key, an INIT past its answer budget - gets an answer that fits, or an empty answer with TC=1 (the question and nothing else), which is never longer than the query either. A resolver that gets TC=1 repeats the query over TCP, and a TCP source cannot be spoofed. `TestUnauthenticatedAnswersAreNeverLongerThanTheQuery` covers about 120 query shapes and `FuzzHandleQueryNeverAmplifies` any bytes.
3. UDP answer bytes are counted per source network (/24, /56 for IPv6), `SOURCE_BYTES_PER_SECOND` (4 MiB/s by default, burst a quarter second). Past it answers become empty TC answers.

The positive answers of the apex (SOA, NS, A) and the delegation check are always longer than their queries, so over UDP they come back truncated and are served over TCP. A resolver that validates a delegation retries over TCP by itself.

#### What an authenticated query may get

An authenticated query may get an answer longer than itself, because it carries data. Two such answers are bounded further:

- **ACCEPT.** The ACCEPT is the one answer that cannot be made no longer than its INIT: the question is echoed in both, and the ACCEPT adds a TXT record of 77 bytes. Padding the INIT does not help either, the padding is part of the question and is echoed; EDNS padding is dropped by recursive resolvers. Measured with a 11-character zone: INIT query 152 bytes, ACCEPT answer 229 bytes, ratio 1.51 (it falls towards 1 for longer zone names). The alternative, TC for every ACCEPT, would make session setup depend on a resolver that retries over TCP, for nothing: an INIT is authenticated by the device key, can only be captured by a resolver on the path, and a captured INIT is answered at most 9 times over UDP (the client sends three racing queries per attempt and makes up to three attempts with the same INIT, and a client on a lossy path must not be left without an answer). **The worst case is therefore 9 x 229 = 2061 bytes reflected at a victim per captured INIT (an INIT is sent once per session start), at a ratio of 1.5 per packet.** The per-network byte budget caps it further.
- **Repeats of a data answer.** The sealed answers of a session are kept for 10 seconds by the counter of the frame that asked (`answer_cache.go`, 16 entries per session). A resolver that lost our answer asks again with the same bytes, and a resolver that got TC=1 asks again over TCP with the same bytes: the counter is the one the replay window has used, so without the cache the data of that answer would be lost and only ARQ would recover it. With the cache the repeat gets the same sealed frame. Over UDP only from the source address that sent the first copy, and at most twice; over TCP at most four times. A captured query sent from another address gets the empty answer. A data answer of 900 bytes to a query of 282 is 3.2 times, but only to the resolver that already got it, and the bytes are the same bytes that resolver was already sent. Frames answered with PONG are not kept.

A pre-session probe is answered once; when the answer is too long for UDP it is truncated, and the TCP repeat finds the probe already used and gets no data: a size that does not fit UDP is not a download MTU, which is what the client then concludes.

## Behaviour that follows from this

- The server never answers an INIT that is unknown, stale, wrongly keyed or malformed, nor a replayed INIT whose cached ACCEPT has been dropped. Frames for unknown sessions and replayed frames get an ordinary empty DNS answer (no data).
- The server has no key to sign a "session lost" message with, so the client treats 90 seconds without any authenticated downlink frame as a lost session and starts a new one (`LivenessTimeout` in the library). A kicked device therefore needs up to 90 seconds to notice. The old unauthenticated ERROR_DROP and SESSION_BUSY answers are no longer sent.
- A pre-session probe is answered once, only while fresh, at most 60 times a minute per device.
- The upload MTU found by probing is the payload a session frame can carry in the same name: the probe is shortened by the difference between the probe envelope and the frame overhead (`uploadProbeSlack`).

## Limits (defaults)

| Limit | Upstream | Here |
| --- | --- | --- |
| UDP read buffer | 65535 | 4096 |
| request queue | 32768 (never below 4096 whatever was configured) | 1024, exactly as configured |
| streams per session | 2000 | 64 |
| ARQ window (server, and the ceiling it announces) | 800 / 8000 | 512 / 512 |
| connect timeout | 120 s (a hidden cap of 15 s applied) | 20 s |
| sessions per server | 255 | 64 (`MAX_ALLOWED_CLIENT_ACTIVE_SESSION`, at most 255) |
| sessions per device | unlimited | 2; a further INIT closes the idlest |
| queries per session | unlimited | 2000/s, burst 4000 (measured peak of a transfer over a lossy loopback path: 1400/s) |
| deferred connect workers | 4 | 64, sharing 1024 queue slots; one session may have 64 connects pending |
| tunnel DNS cache | 50000 records | 4096 |
| UDP answer bytes per source /24 | unlimited | 4 MiB/s |
| TCP 53 | none | 16 connections per source, 256 in all, 10 s idle |
| client UDP read buffer, receive queue | 65535, 4096 | 4096, 512 |

### Worst-case memory at 64 sessions

Fixed: the request queue, 1024 x 4096 = 4 MiB (only when the server owns its sockets; a host that calls `HandleQuery` has no queue); the answer caches, 16 frames x at most 4.3 KiB x 64 sessions = 4.4 MiB; the per-source-network budget, at most 16384 entries; 256 TCP connections; the tunnel DNS cache, 4096 records. Garbage from 120000 different source networks grew the heap by 2 MiB (`TestGarbageDoesNotGrowServerStateWithoutBound`).

An open stream that carries nothing costs 41 KiB and two goroutines (measured: 64 sessions x 8 streams = 21 MiB, `TestIdleSessionTableFootprint`; the ARQ default queue of received segments, four windows, would cost 64 KiB per stream alone, so the fork sets it to a window and a quarter). 64 sessions x 64 streams, all open and idle: 168 MiB.

A stream that moves data also holds, in its send buffer, at most one ARQ window of downlink: 512 packets of at most the session's download MTU, which discovery finds near 870 bytes behind a resolver with an EDNS size of 1232 (4096 at the very most): **512 x 870 = 445 KiB per stream, 2 MiB at 4096**. All 64 streams of all 64 sessions backed up with a full window at the same time is **1.8 GiB** (8 GiB at an MTU of 4096). That needs 4096 connections that all stall on the client's side at once; it is a bound, not an expectation. The host sets the limit that fits its box with `MaxSessions` and `MaxStreamsPerSession`: 64 sessions x 8 streams x 445 KiB = 225 MiB.

## Zone responder, hooks and embedding

`mgdns` is the facade; the code lives in `internal/` and is not importable from outside the module.

Server (`mgdns.NewServer(ServerConfig)`):

| | |
| --- | --- |
| `Start(ctx)` | the cleanup of expired sessions and the deferred workers; no socket is opened |
| `HandleQuery(src netip.AddrPort, packet []byte, maxResp int, tcp bool) []byte` | one DNS message in, the answer out (empty: send nothing) |
| `ServeTCPConn(ctx, conn)` | the TCP framing and limits, for hosts that accept TCP themselves |
| `SetCredentialIndex(*CredentialIndex)` | replaces the credentials atomically; sessions of removed or re-keyed credentials are closed |
| `CloseCredential(id) int` | closes every session of a credential at once; the next query finds no session. Cached ACCEPTs of it are dropped |
| `Sessions() []SessionInfo` | credential id, resolver address, age, last activity, streams, queries, DNS bytes in and out |
| `Stats() QueryStats` | refused, truncated, replays, answers from the cache, rate-limited, limited probes, silent |
| `SetHooks(Dial, ResolveDNS)` | `Dial(ctx, credentialID, network, address)` instead of `net.Dial`; `ResolveDNS(ctx, credentialID, query)` instead of `DNS_UPSTREAM_SERVERS` |
| `NewServerFromConfig` + `Serve(ctx)` | standalone mode: the sockets of the TOML configuration; `cmd/server` is this |

The external SOCKS5 mode (`USE_EXTERNAL_SOCKS5`, `SOCKS5_*`) is removed. A target chosen by a client passes `validateSOCKSTargetHost` (empty name, `localhost`, private/loopback/link-local/shared/benchmark literals) and, without a `Dial` hook, a second check in the dialer after resolution: a name that resolves to a private address is refused. With a hook the host decides. The fixed target of `PROTOCOL_TYPE = "TCP"` is the operator's and may be local.

Client (`mgdns.NewClient(ClientConfig)`): no TOML, no file, no listener (no SOCKS, no local DNS, no console).

| | |
| --- | --- |
| `Start(ctx)` | arms the client; the session comes up at the first `DialContext` or `ResolveDNS` |
| `DialContext(ctx, "tcp", "host:port") (net.Conn, error)` | an in-process connection (two `net.Pipe`s, so `CloseWrite` works) to a tunneled stream; the name is resolved by the server; a `*mgdns.DialError` (with the SOCKS5 reply code) when the server cannot connect |
| `ResolveDNS(ctx, query) ([]byte, error)` | a DNS query resolved by the server |
| `Ready() bool` | an atomic flag, safe from any goroutine |
| `ClientConfig.Control` | called for every socket to a resolver before it is bound or connected (`IP_UNICAST_IF`, `IP_BOUND_IF`, ...) |
| `ClientConfig.Resolvers []netip.AddrPort` | numbers only; a subnet is never expanded (the parser of the standalone client refuses it too) |
| `ClientConfig.LoadRanking`, `SaveRanking` | the resolver ranking goes to the host instead of a file; the ranked resolvers come first next time |
| `ClientConfig.IdleTimeout` | the session ends after 5 minutes (default) without an open stream; the next dial starts it again |
| `ClientConfig.LivenessTimeout` | silence of the server after which the session is taken for lost (90 s) |

## Issue 202 ("goes quiet after about 3.5 minutes")

- 3 min 30 s is the time to live of a SOCKS5_SYN (120 s) plus the wait for the answer to its reset (90 s): a SYN that was never answered from the start.
- **H3 (head of the queue in the deferred connects) is confirmed.** A connect holds its worker until it ends and every worker has a FIFO. With 4 workers, 10 black-hole targets and a connect timeout of 2 s an ordinary connect waited 4.3 s (two timeouts); at the old defaults (4 workers, connect timeout capped at 15 s) it would wait about 30 s, and more for more black holes. Fixed by 64 workers (the least loaded takes a new lane), a 20 s timeout and a per-session limit of pending connects: an ordinary connect behind 10 black holes is answered in about 10 ms (`TestBlackHoleConnectsDoNotDelayOtherConnects`).
- A soak test (`TestFacadeSoak`, 5 minutes by default, `MGDNS_SOAK_MINUTES=30` for the full run) keeps a long-lived connection busy, opens a fresh connection every 4 seconds and a connect to a black hole every 11 seconds over a path with 3 % loss, duplication and repeats, and checks that nothing waits long.
- H1 (versions) does not apply, H4 does not apply to the sealed downlink, H2 and H5 are about resolvers and can only be checked in the field.

## Changed files

| File | Reason |
| --- | --- |
| `mgdns.go`, `server.go`, `client.go`, `credential.go` | The public facade. |
| `README.MD`; `README_ES/FA/IT/RU/ZH.MD` removed | Describe this fork; the translations described upstream. |
| `MISTGATE.md` | This file. |
| `internal/security/protocol.go` | Credentials and the atomic credential index, INIT/ACCEPT, key schedule, directional frame AEAD, replay window, probes and probe limiter. |
| `internal/security/codec.go`, `encryption_key.go` (removed) | Cipher methods 0-5 and the shared `ENCRYPTION_KEY` / `encrypt_key.txt`. |
| `internal/compression` (removed), `internal/vpnproto/payload.go` (removed) | Compression. |
| `internal/vpnproto/builder.go`, `parser.go` | The inner packet has no session id, cookie, header check or compression byte; no codec in the parser. |
| `internal/vpnproto/session_accept.go` | The ACCEPT policy block without the session id and cookie, the compression pair and minimum size. |
| `internal/arq/arq.go` | Two changes: `PushTXPacket` and `Config` lose the compression type; `retransmitPriorityKinds` reads `sndNxt` under the lock (a data race with `ioLoop`, found by `go test -race` on the facade test). |
| `internal/dnsparser/transport.go`, `response.go`, `respond.go` | Opaque response payload, TXT chunking over the whole frame, pointer owners, own OPT, no echo of options, flags, `BuildResponse`/`BuildTruncated`, random message IDs. |
| `internal/domainmatcher/matcher.go` | `ActionRefused`; labels for every in-zone decision. |
| `internal/udpserver/server_protocol.go` | Demultiplexing of frames, INIT and probes; INIT cache; probe answers; repeated frames. |
| `internal/udpserver/server_query.go`, `server_zone.go`, `answer_cache.go`, `server_tcp.go`, `server_credentials.go`, `hooks.go` | `HandleQuery` and its size policy, the zone responder, the answer cache, TCP 53, credentials and sessions, hooks. |
| `internal/udpserver/socks5_upstream.go` | External SOCKS5 mode removed; hook dial; second check of the resolved address. |
| `internal/udpserver/server.go`, `server_ingress.go`, `server_session.go`, `server_postsession.go`, `server_deferred.go`, `server_runtime.go`, `session.go`, `dns_tunnel.go` | Credential index in the server, per-session cipher, sealed downlink, removal of the session cookie and of the invalid-cookie tracker, `Start`, limits, hooks, the connect worker pool. |
| `internal/client/client.go`, `session.go`, `async_runtime.go`, `tunnel_query.go`, `tunnel_runtime.go`, `dispatcher.go`, `handlers/packed_control_handler.go` | Handshake, a fresh counter for every copy of a duplicated packet, sealed uplink and downlink, INIT rebuilt before it goes stale, silent-downlink and counter-limit session restart; library mode (no listener), atomic `SessionReady`, 4096 byte read buffer. |
| `internal/client/library.go`, `stream_client.go`, `socks_manager.go`, `protected_socket.go` | `OpenStream` and `ResolveDNS` for the facade; the connect result goes to a channel instead of a SOCKS reply; the `Control` hook. |
| `internal/client/mtu.go`, `micro_burst.go` | Authenticated probes and the probe/frame size compensation; discovery and selection logic is as upstream. |
| `internal/client/client_utils.go` | Banner no longer prints a cipher number. |
| `internal/config/client.go`, `server.go`, `client_resolvers.go` | `DEVICE_CREDENTIAL` replaces `DATA_ENCRYPTION_METHOD`, `ENCRYPTION_KEY`, `ENCRYPTION_KEY_FILE`; the `INVALID_COOKIE_*`, compression and external SOCKS5 settings are gone; new zone, limit and library settings; a subnet in the resolver list is refused instead of expanded. |
| `internal/logger/logger.go` | `NewWithWriter`. |
| `client_config.toml.simple`, `server_config.toml.simple` | The same settings in the sample configs. |
| `cmd/client/main.go`, `cmd/server/main.go` | One standalone credential; no `-genkey`; the server runs through the facade. |
| `docker/entrypoint/*`, `docker/smoke-test.sh`, `server_linux_install.sh`, `scripts/bench/bench.go`, `.github/workflows/build-go.yml`, `build-test.yml` | No key generation or key file; they use a credential. |

Tests: `internal/security/protocol_test.go` (with an independent reference in `reference_test.go`), `internal/udpserver/server_protocol_test.go`, `server_protocol_replay_test.go`, `e2e_test.go`, `server_query_test.go`, `server_amplification_test.go`, `server_policy_test.go`, `server_credentials_test.go`, `deferred_connect_test.go`, `server_memory_test.go`, `internal/dnsparser/respond_test.go`, `internal/client/session_liveness_test.go`, and in the module root `mgdns_e2e_test.go` and `mgdns_soak_test.go`. Upstream tests were changed only to build clients and servers with a credential, to drop the cookie and the compression byte, where the format or an answer changed, and to remove data races in test doubles (`testNetConn.closed` is atomic, `testLogger` stops forwarding when its test ends).

## Running the tests

- `go test ./...` and `go test -race ./...` both pass without skips; the soak test of the facade makes the module root take about 6 minutes. `-short` skips the transfers, the soak, the memory measurements and the long fuzz-style loops (the whole suite then takes under a minute).
- `MGDNS_SOAK_MINUTES=30 go test -run TestFacadeSoak -timeout 60m .` is the full 30-minute soak.
- Fuzz targets: `FuzzFrameParser`, `FuzzSessionInit`, `FuzzSessionAccept`, `FuzzProbe` (`internal/security`), `FuzzParse` (`internal/vpnproto`), `FuzzExtractVPNResponsePayload` (`internal/dnsparser`), `FuzzHandleQueryNeverAmplifies` and `FuzzHandleQueryWithSession` (`internal/udpserver`); each ran 60 seconds without a finding. Run one with `go test -run NONE -fuzz '^FuzzHandleQueryNeverAmplifies$' -fuzztime 60s ./internal/udpserver`.
- `TestIntegratedResolverManagerAcceptance` (upstream) has one absolute 15 second deadline for a whole discovery pass and can fail on a machine that is busy with other test packages; run `go test -p 2` there.

## Merging newer upstream revisions

Merge, do not rebase: `git fetch upstream && git merge upstream/main` on the `mistgate` branch.

- `internal/vpnproto`, `internal/security` and `internal/dnsparser` define the wire format. Resolve conflicts there in favour of this fork; upstream changes in those packages are not taken (port a fix by hand if it is independent of the format).
- `internal/arq`, the balancer, resolver discovery and MTU selection are kept as upstream so that merging them stays easy. The only fork changes near them are the probe envelope and size accounting in `internal/client/mtu.go` and `micro_burst.go`, the dropped compression argument of `PushTXPacket` and the lock around `sndNxt`; keep those when merging selection or discovery fixes.
- After a merge run `go vet ./...`, `go test ./...` and, for the protocol, `go test -run 'Pinned|Reference' ./internal/security`: the pinned vectors must not change.
