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

Code two Plugins need identically goes in the `internal` module, not in a
second copy: a copy is what drifts, and the Plugin it drifts in is the one that
loses a key's ACL or misses a failed reload. `internal` takes no third-party
dependency, so a Plugin importing it inherits none, and nothing in it is
Plugin-specific: a message a reader sees is worded by the Plugin, in its own
catalog, from the data `internal` returns.

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

## Text a reader sees

Everything `describe` and `discover` answer for a person to read is text per
language (`l10n.Text` from the contract module): the Plugin's description, each
setting's label and description, every warning and every extra-data label.
English is required; an answer holding a text without it is refused as
malformed. A Plugin answers in every language at once, because the answer is
stored and read later by people who do not share one.

To add or change a text:

- Call `T("<id>", "<English>", "name", value, ...)` from `internal/ops`. The
  ID is explicit, prefixed by the Plugin and named for where the text appears
  (`nginx.setting.reload.description`, `nginx.warning.shared_certificate`),
  never derived from the English. The English is a string literal at the call.
- Add the Spanish under the same ID in `internal/ops/locales/es.json`, with
  the same `{name}` placeholders and the same Markdown spans around the same
  literals.
- One sentence is one message. Values found on the host go in as
  placeholders; translated fragments are never joined. When a value is itself
  worded (a list whose items say "reloaded with"), build the message once per
  language, as `perLanguage` does in `nginx`.
- `TestCatalog` in each `internal/ops` fails on a message with no translation,
  a translation no message uses, and placeholders that differ.

Not translated, and left exactly as produced: what `deploy` prints while it
runs, a program's or a parser's own error text, setting keys, values and
defaults, paths, commands, and a label that is itself a literal, such as the
directive name `ssl_certificate`, which is English alone.

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
