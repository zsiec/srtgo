package core

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestNoForbiddenImports enforces the Sans-I/O purity invariant: no
// non-test source file in this package may directly import "net" or "time".
// Durations and timestamps use the clock package's value types; destination
// addresses are attached by the host. (clock/packet legitimately pull time/net
// transitively for their value types — this gate is about direct imports,
// matching the source-discipline rule documented in docs/sansio-migration.md.)
func TestNoForbiddenImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]string{
		`"net"`:  "net",
		`"time"`: "time",
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			if pkg, bad := forbidden[imp.Path.Value]; bad {
				t.Errorf("%s directly imports %q: the Sans-I/O core must not import net or time "+
					"(use clock types; addresses are the host's job)", name, pkg)
			}
		}
	}
}
