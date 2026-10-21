// Command env-docs-check verifies that every SAFE_ZONE_* setting the Go code
// reads is documented in .env.example.
//
// A setting that exists in the code but not in the example file is invisible
// to an operator: they cannot discover it, cannot tell what it does, and
// cannot tell what the safe default is. The gap is silent in both directions.
//
// The check reads the code as text rather than importing the packages,
// because the settings are read through os.Getenv at call time in a dozen
// different helpers, and a textual scan sees the same strings a maintainer
// would.
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
)

// settingPattern matches a complete setting name in a string literal.
var settingPattern = regexp.MustCompile(`"SAFE_ZONE_[A-Z0-9_]+"`)

// examplePattern matches a setting documented at the start of a line, either
// as a live value or as a commented-out line. A commented entry counts as
// documented: some settings must not be pinned to a value, and the operator
// still needs to know they exist and what happens when they are unset.
var examplePattern = regexp.MustCompile(`(?m)^(?:|#\s*)(SAFE_ZONE_[A-Z0-9_]+)\s*=`)

// ignoredPrefixes are setting families that are documented by their members
// rather than as a whole name, because the code composes the longer name at
// runtime.
var ignoredPrefixes = []string{
	"SAFE_ZONE_URL_ML_FEEDBACK_",
}

func main() {
	os.Exit(run())
}

func run() int {
	repoRoot := flag.String("repo-root", ".", "repository root")
	flag.Parse()

	// Every file this tool reads is opened through a root scoped to the
	// repository. A path that escapes the root, including through a
	// symlink, is refused by the filesystem layer rather than by a check
	// this tool would have to remember to make.
	root, err := os.OpenRoot(*repoRoot)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = root.Close() }()

	codeSettings, err := collectCodeSettings(root)
	if err != nil {
		return fail(err)
	}

	exampleSettings, err := collectExampleSettings(root)
	if err != nil {
		return fail(err)
	}

	documented := make(map[string]bool, len(exampleSettings))
	for _, name := range exampleSettings {
		documented[name] = true
	}

	var missing []string
	for _, name := range codeSettings {
		if documented[name] || isIgnored(name) {
			continue
		}
		missing = append(missing, name)
	}

	if len(missing) == 0 {
		fmt.Printf("env-docs-check: every SAFE_ZONE_* setting read by the code is documented in .env.example (%d checked)\n", len(codeSettings))
		return 0
	}

	fmt.Fprintf(os.Stderr, "env-docs-check: %d settings are read by the code but missing from .env.example:\n", len(missing))
	for _, name := range missing {
		fmt.Fprintf(os.Stderr, "  - %s\n", name)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Add each one to .env.example with a comment that says what it does and what")
	fmt.Fprintln(os.Stderr, "the default is. An undocumented setting is one an operator cannot configure,")
	fmt.Fprintln(os.Stderr, "cannot audit, and cannot reason about.")
	return 1
}

// isIgnored reports whether a name belongs to a documented family.
func isIgnored(name string) bool {
	for _, prefix := range ignoredPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// collectCodeSettings scans the Go sources for settings the code reads.
func collectCodeSettings(root *os.Root) ([]string, error) {
	seen := make(map[string]struct{})

	for _, dir := range []string{"internal", "cmd"} {
		if _, err := fs.Stat(root.FS(), dir); err != nil {
			continue
		}
		err := fs.WalkDir(root.FS(), dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			content, readErr := fs.ReadFile(root.FS(), path)
			if readErr != nil {
				return readErr
			}
			for _, match := range settingPattern.FindAllString(string(content), -1) {
				seen[strings.Trim(match, `"`)] = struct{}{}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// collectExampleSettings reads the documented settings from .env.example.
func collectExampleSettings(root *os.Root) ([]string, error) {
	content, err := fs.ReadFile(root.FS(), ".env.example")
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	for _, match := range examplePattern.FindAllStringSubmatch(string(content), -1) {
		seen[match[1]] = struct{}{}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "env-docs-check: %v\n", err)
	return 1
}
