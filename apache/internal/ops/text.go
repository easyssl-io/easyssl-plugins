package ops

import (
	"embed"
	"errors"
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

// perLanguage builds a text one language at a time, for a message one of
// whose values is itself worded: a list whose items each say "reloaded with"
// has to be Spanish inside the Spanish sentence, and T fills every language
// from one set of values. render is called once per language with that
// language's printer and words the whole message with it.
func perLanguage(render func(p l10n.Printer) string) l10n.Text {
	t := l10n.Text{}
	for _, lang := range l10n.Supported() {
		t[lang] = render(catalog.In(lang))
	}
	return t
}

// worded is an error whose text this Plugin wrote, in every language, so a
// warning made from it reads in the reader's language. Any other error is
// what a program or a parser said and stays as it was produced.
type worded struct{ text l10n.Text }

func (e worded) Error() string { return e.text.In(l10n.English) }

// textOf is an error as a warning: its own wording per language when this
// Plugin wrote it, else the error's text as produced.
func textOf(err error) l10n.Text {
	var w worded
	if errors.As(err, &w) {
		return w.text
	}
	return literal(err.Error())
}

// literal is a text that is the same in every language because it is not
// prose: a directive name, or what a program said in its own words.
func literal(s string) l10n.Text {
	return l10n.Text{l10n.English: s}
}

// hostLanguage is the language relocate speaks to the person running the
// Agent's command: EASYSSL_LANG when it names a supported language, which is
// how the Agent passes on the language it speaks, else the locale's, else
// English. Unlike discovery's answer, relocate's output is read once, on the
// host, by that person.
func hostLanguage() string {
	if l, ok := l10n.Base(os.Getenv("EASYSSL_LANG")); ok {
		return l
	}
	if l, ok := l10n.FromLocale(os.Getenv); ok {
		return l
	}
	return l10n.English
}
