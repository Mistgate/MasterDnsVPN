# MasterDnsVPN fork for Mistgate

A fork of [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) (a VPN tunnel carried in DNS queries and TXT answers), based on upstream commit `b996849db0c1856024af6a00b39cd304e23dbe11`.

**The wire format of this fork is not compatible with upstream clients or servers.** Do not point an upstream client at this server or the other way round.

## What is changed and why

- **One credential per device.** Each device has an 8-byte `kid` and a 32-byte key. The server looks the device up by `kid` in an index that the embedding application can replace atomically. Upstream has a single key shared by every client.
- **Authenticated encryption in both directions.** Every session frame is ChaCha20-Poly1305. Upstream answers were sent in clear text and could be forged; here nothing of the tunnel except the session id and a frame counter is readable on the wire.
- **Session setup with fresh keys.** A timestamped INIT under the device key carries an ephemeral X25519 key, the answer carries the server's, and per-direction keys are derived with HKDF-SHA256. Recording the traffic and later stealing the device key does not reveal past sessions.
- **Replay protection.** A 32-bit frame counter doubles as the AEAD nonce; each side keeps a 2048-frame replay window. A replayed frame gets an empty answer. A replayed INIT gets the identical cached answer and no second session.
- **No weak modes.** The None, XOR, bare ChaCha20 and AES-GCM modes, the shared key file, the clear session cookie and the header checksum are removed, so there is no setting that turns authentication off.
- **Pre-session MTU probes are authenticated** with the device key, are accepted once, only while fresh, and are limited to 60 per minute per device.
- **A protocol version byte** makes a future incompatible change refuse cleanly.

The unauthenticated part of the answers (the DNS envelope, TXT chunk numbers) is unchanged. The ARQ, resolver balancing, discovery and MTU selection code is kept as upstream.

`MISTGATE.md` lists every changed file with the reason and describes how newer upstream revisions are merged.

## Standalone use

`cmd/server` and `cmd/client` still run on their own for testing. Each reads one credential, `DEVICE_CREDENTIAL = "<16 hex kid>.<key>"`, where the key is 64 hex characters or 43 base64url characters without padding, from its config (or the `-device-credential` flag). Applications that embed the server supply the whole credential set through the credential index instead.

## Seeing the changes

```
git diff b996849d mistgate
```

## License and authorship

MIT, unchanged. The upstream copyright notice is kept in [LICENSE](LICENSE).

## Who uses it

[Mistgate](https://github.com/Mistgate/mistgate).
