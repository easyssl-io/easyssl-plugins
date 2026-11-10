package ops

import (
	"embed"
	"os"

	"github.com/easyssl-io/easyssl-contract/l10n"
)

// The Plugin's translations, one file per language beside this one. English
// has no file: it stands at each call site, next to the ID.
//
//go:embed locales/*.json
var locales embed.FS

var catalog = l10n.MustLoad(locales, "locales")

// T is one reader-facing text in every language this build carries, because
// what a Plugin answers is stored and read later by people who do not share a
// language. The ID names where the text appears and is never derived from the
// English, so rewording the English orphans no translation.
func T(id, english string, args ...any) l10n.Text {
	return catalog.Text(id, english, args...)
}

// hostLanguage is the language relocate speaks to the person running the
// Agent's command: EASYSSL_LANG when it names a supported language, which is
// how the Agent passes on the language it speaks, else the locale's, else
// English.
func hostLanguage() string {
	if l, ok := l10n.Base(os.Getenv("EASYSSL_LANG")); ok {
		return l
	}
	if l, ok := l10n.FromLocale(os.Getenv); ok {
		return l
	}
	return l10n.English
}
