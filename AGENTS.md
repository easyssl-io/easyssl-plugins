# AGENTS.md

Guidance for AI coding agents working in `easyssl-plugins`. The file is named
`AGENTS.md` because that is the name the tools read; "agent" in this file means
an AI coding agent, while **Agent** capitalized means easySSL's own
host-installed component. `README.md` says what these plugins are and how they
build; this file is what a change to one must respect.

## Build

Each plugin is a separate module, so build inside the one you changed:

```bash
cd generic-cli && go build ./... && go test ./... && go vet ./...
```

Do not add a module at the repository root, and do not merge two plugins into
one module. The split is what keeps a browser-automation plugin's dependencies
out of a minimal plugin's graph.

## What a plugin is

A plugin is a standalone executable, not a library linked into the Agent. The
Agent fetches it, checks its content digest against the catalog entry before a
single line of it runs, installs it, and then speaks to it over stdio. Two
things follow, and both are easy to break by accident:

- **A plugin never becomes an Agent dependency.** Nothing in the Agent imports
  this module, and nothing here may assume it can call back into the Agent. The
  stdio protocol is the whole contract.
- **A plugin runs with the Agent's privileges**, which on most hosts means root.
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
