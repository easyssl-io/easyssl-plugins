// Package buildversion is a Plugin build's own version, which its describe
// answer and its deploy output carry.
package buildversion

// Version is set from the Plugin's release tag, `<plugin>/vX.Y.Z`, with
// `-ldflags -X` when a release is built. Every other build, one made straight
// from a checkout included, reports the version every Plugin keeps until its
// first release. A variable rather than a constant, since `-X` can set only a
// variable.
var Version = "0.0.1"
