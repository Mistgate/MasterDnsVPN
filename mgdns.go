// Package mgdns is the public facade of the Mistgate fork of MasterDnsVPN: a
// DNS tunnel whose server and client are embedded in another program, with no
// sockets, files, flags or listeners of their own.
//
// The server (Server) is fed DNS messages by its host: the host listens on UDP
// and TCP port 53, calls HandleQuery for every message and writes back what it
// returns. The host decides where the tunneled connections go (the Dial hook)
// and who resolves the tunneled DNS queries (the ResolveDNS hook); both get the
// id of the credential whose session asked.
//
// The client (Client) opens tunneled connections as net.Conn values (DialContext)
// and answers DNS queries through the tunnel (ResolveDNS). Every socket it opens
// to a resolver passes through ClientConfig.Control.
//
// Every device has its own credential, "<kid>.<key>": kid is 16 hex characters,
// key is 32 bytes as 64 hex characters or 43 base64url characters.
package mgdns

// Version names the upstream commit this fork is based on.
const Version = "b996849db0c1856024af6a00b39cd304e23dbe11"
