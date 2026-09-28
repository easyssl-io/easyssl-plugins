# AGENTS.md

Guidance for AI coding agents working in `easyssl-plugins`. The file is named
`AGENTS.md` because that is the name the tools read; "agent" in this file means
an AI coding agent, while **Agent** capitalized means easySSL's own
host-installed component. `README.md` says what these Plugins are and how they
build; this file is what a change to one must respect.

## Build

Each Plugin is a separate module, so build inside the one you changed:

```bash
cd generic-cli && go build ./... && go test ./... && go vet ./...
```

Do not add a module at the repository root, and do not merge two Plugins into
one module. The split is what keeps a browser-automation Plugin's dependencies
out of a minimal Plugin's graph.

## What a Plugin is

A Plugin is a standalone executable, not a library linked into the Agent. The
Agent fetches it, checks its content digest against the catalog entry before a
single line of it runs, installs it, and then speaks to it over stdio. Two
things follow, and both are easy to break by accident:

- **A Plugin never becomes an Agent dependency.** Nothing in the Agent imports
  this module, and nothing here may assume it can call back into the Agent. The
  stdio protocol is the whole contract.
- **A Plugin runs with the Agent's privileges**, which on most hosts means root.
  It writes private keys and restarts services. Treat every input as
  attacker-influenced: paths arrive from users and from parsed host
  configuration, and install commands are user-supplied strings.
- **A command a Plugin runs for the user fails on its first failing line.**
  `generic-cli` runs the install command under `/bin/sh -e`, because a script's
  own exit status is only its last line's: `ls /missing; echo done` exits 0,
  and a Deployment marked succeeded with nothing installed is the one outcome
  a Plugin must never produce. A line allowed to fail says so with `|| true`;
  a script that wants last-line semantics says `set +e` on its first line.
  The limit is POSIX's: `-e` does not act on a failure on the left of `&&`
  or `||`, or inside a pipeline, so a command that must fail goes on its own
  line, and everything that promises fail-fast says so.

## Dependencies

Prefer the Go standard library. A Plugin ships to every host that installs it
and is meant to be auditable by the people whose keys it handles, so each
third-party dependency has to earn its place and be justified in the change that
adds it.

## Testing

Plugins touch the filesystem and run commands, so the tests worth writing live
at that boundary: given a target path and a command, assert what was written and
what ran. Cover the failure paths deliberately, above all the one where a path
cannot be written, because a Plugin that half-writes certificate material is
worse than one that refuses to start.

## Conventions

American English. Capitalize Organization, Agent, Server, Plugin, Certificate,
Target and Deployment whenever they name easySSL's own records or components;
write "web console" in full for easySSL's browser UI. Keep a genuinely generic
technical role lowercase, such as an ACME client or a CNAME target. This
repository is public and self-contained: never cite a document, identifier, or
issue that lives in a private repository. State the property directly instead.
