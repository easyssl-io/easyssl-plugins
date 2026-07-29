// Package plugins is the module root for the first-party easySSL plugins.
//
// It holds no code of its own: each plugin lives under cmd/ and builds to its
// own executable, which a Client fetches, verifies and drives over stdio.
package plugins
