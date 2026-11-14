package relocation

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "certificate.pem")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for to, want := range map[string]Problem{
		f:                         0,
		"etc/ssl/a.pem":           NotAbsolute,
		filepath.Join(d, "nope"):  Missing,
		d:                         NotRegular,
		filepath.Join(d, `a"b`):   Unquotable,
		filepath.Join(d, "a$b"):   Unquotable,
		filepath.Join(d, "a\nb"):  Unquotable,
		filepath.Join(d, `a\b`):   Unquotable,
		filepath.Join(d, "a'b"):   Unquotable,
		filepath.Join(d, "a`b"):   Unquotable,
		filepath.Join(d, "a\x00"): Unquotable,
	} {
		if got := Check(to); got != want {
			t.Errorf("Check(%q) = %d, want %d", to, got, want)
		}
	}
}

func TestDiff(t *testing.T) {
	missing, extra := Diff([]int{1, 2, 3, 3}, []int{3, 4, 2, 4})
	if !slices.Equal(missing, []int{1}) || !slices.Equal(extra, []int{4}) {
		t.Fatalf("Diff = %v, %v", missing, extra)
	}
	if m, e := Diff([]string{"a"}, []string{"a"}); m != nil || e != nil {
		t.Fatalf("equal sets: %v, %v", m, e)
	}
}

func TestApply(t *testing.T) {
	got, err := Apply([]byte("ab cd ef"), []Edit{{6, 8, "XY"}, {0, 2, "\"z z\""}, {0, 2, "\"z z\""}})
	if err != nil || string(got) != "\"z z\" cd XY" {
		t.Fatalf("Apply = %q, %v", got, err)
	}
	if _, err := Apply([]byte("abcd"), []Edit{{0, 3, ""}, {2, 4, ""}}); err == nil {
		t.Error("overlapping edits were applied")
	}
	if _, err := Apply([]byte("ab"), []Edit{{1, 5, ""}}); err == nil {
		t.Error("an edit past the end was applied")
	}
}

func TestNote(t *testing.T) {
	for in, want := range map[string]string{
		`now managed by easySSL; check the other "managed by Certbot" lines`: `now managed by easySSL; check the other "managed by Certbot" lines`,
		"  first line  \nsecond line":                                        "first line",
		"carriage\rreturn":                                                   "carriage",
		"tab\tand bell\a":                                                    "taband bell",
		`ends in a continuation \\`:                                          "ends in a continuation",
		`managed \ \`:                                                        "managed",
		"blanks and backslashes \\ \t\\\\  ":                                 "blanks and backslashes",
		"":                                                                   "",
		strings.Repeat("é", 150):                                             strings.Repeat("é", 100),
	} {
		if got := Note(in); got != want {
			t.Errorf("Note(%q) = %q, want %q", in, got, want)
		}
	}
}
