# AGENTS.md

Guidance for coding agents in `easyssl-plugins`. `README.md` says what these
plugins are and how they build; this file is what a change to one must respect.

## Build

```bash
go build ./... && go test ./... && go vet ./...
```

## What a plugin is

A plugin is a standalone executable, not a library linked into the Client. The
Client fetches it, checks its content digest against the catalog entry before a
single line of it runs, installs it, and then speaks to it over stdio. Two
things follow, and both are easy to break by accident:

- **A plugin never becomes a Client dependency.** Nothing in the Client imports
  this module, and nothing here may assume it can call back into the Client. The
  stdio protocol is the whole contract.
- **A plugin runs with the Client's privileges**, which on most hosts means root.
  It writes private keys and restarts services. Treat every input as
  attacker-influenced: paths arrive from users and from parsed host
  configuration, and reload commands are user-supplied strings.

## Dependencies

Prefer the Go standard library. A plugin ships to every host that installs it
and is meant to be auditable by the people whose keys it handles, so each
third-party dependency has to earn its place and be justified in the change that
adds it.

## Testing

Plugins touch the filesystem and run commands, so the tests worth writing live
at that boundary: given a target path and a command, assert what was written and
what ran. Cover the failure paths deliberately, above all the one where a path
cannot be written, because a plugin that half-writes certificate material is
worse than one that refuses to start.
