package ops

import (
	"embed"

	"github.com/easyssl-io/easyssl-contract/l10n"
)

// The Plugin's translations, one file per language beside this one. English
// has no file: it stands at each call site, next to the ID.
//
//go:embed locales/*.json
var locales embed.FS

var catalog = l10n.MustLoad(locales, "locales")

// T is one reader-facing text in every language this build carries. A Plugin
// answers in all of them rather than in one, because what it answers is
// stored and read later by people who do not share a language.
//
// The ID names where the text appears and is never derived from the English,
// so rewording the English orphans no translation.
func T(id, english string, args ...any) l10n.Text {
	return catalog.Text(id, english, args...)
}
