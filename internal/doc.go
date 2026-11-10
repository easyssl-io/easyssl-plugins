// Package internal holds nothing itself. Its packages are the code more than
// one Plugin in this repository needs identically: replacing a file on the
// host (hostfile), reading certificates and keys (pemfile), asking a server
// over TLS which certificate it presents (tlscheck), and pointing a
// configuration at other files (relocation).
//
// It is one module of its own, so a Plugin that needs none of it does not
// depend on it, and its path sits under internal/, so Go lets only this
// repository's Plugins import it and it is not an API anyone else can come to
// rely on.
package internal
