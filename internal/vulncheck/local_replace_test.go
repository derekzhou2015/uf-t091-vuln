// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/osv"
)

// localTextVuln mirrors an advisory for golang.org/x/text that affects
// v0.3.0 and is fixed at v0.3.7, with a symbol-level package entry.
func localTextVuln() *osv.Entry {
	return &osv.Entry{
		ID: "GO-LOCAL-0001",
		Affected: []osv.Affected{{
			Module: osv.Module{Path: "golang.org/x/text"},
			Ranges: []osv.Range{{
				Type:   osv.RangeTypeSemver,
				Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "0.3.7"}},
			}},
			EcosystemSpecific: osv.EcosystemSpecific{
				Packages: []osv.Package{{
					Path:    "golang.org/x/text/language",
					Symbols: []string{"Parse"},
				}},
			},
		}},
	}
}

// localReplaceModule is what the go command produces for
//
//	replace golang.org/x/text v0.3.0 => ../localmods/x-text
//
// The outer module keeps the go.mod-declared version while the local
// replacement carries a filesystem path and no version.
func localReplaceModule() *packages.Module {
	return &packages.Module{
		Path:    "golang.org/x/text",
		Version: "v0.3.0",
		Replace: &packages.Module{
			Path: "../localmods/x-text",
			Dir:  "C:/work/localmods/x-text",
		},
	}
}

func TestIsLocalReplace(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  *packages.Module
		want bool
	}{
		{"relative local", &packages.Module{Path: "../localmods/x-text"}, true},
		{"dot local", &packages.Module{Path: "./x-text"}, true},
		{"absolute local", &packages.Module{Path: "C:/work/x-text"}, true},
		// A replacement that pins a version is another module, not a
		// filesystem replacement, even if its path looks local.
		{"versioned is module replace", &packages.Module{Path: "../local/x", Version: "v1.0.1"}, false},
		{"module replace", &packages.Module{Path: "golang.org/x/text", Version: "v0.3.0"}, false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLocalReplace(tc.mod); got != tc.want {
				t.Errorf("isLocalReplace(%+v) = %v, want %v", tc.mod, got, tc.want)
			}
		})
	}
}

func TestModPathVersionLocalReplace(t *testing.T) {
	// Explicitly versioned filesystem replace: keep the original module
	// identity and fall back to the go.mod-declared version.
	local := localReplaceModule()
	if got := modPath(local); got != "golang.org/x/text" {
		t.Errorf("modPath(local replace) = %q, want golang.org/x/text", got)
	}
	if got := modVersion(local); got != "v0.3.0" {
		t.Errorf("modVersion(local replace) = %q, want v0.3.0", got)
	}

	// Module-to-module replace keeps using the replacement identity.
	moduleReplace := &packages.Module{
		Path:    "example.mod/a",
		Version: "v2.0.0",
		Replace: &packages.Module{Path: "example.mod/b", Version: "v1.0.0"},
	}
	if got := modPath(moduleReplace); got != "example.mod/b" {
		t.Errorf("modPath(module replace) = %q, want example.mod/b", got)
	}
	if got := modVersion(moduleReplace); got != "v1.0.0" {
		t.Errorf("modVersion(module replace) = %q, want v1.0.0", got)
	}

	// A versionless module without replace stays versionless so the
	// existing conservative "unknown version" behavior is preserved.
	versionless := &packages.Module{Path: "example.mod/c"}
	if got := modVersion(versionless); got != "" {
		t.Errorf("modVersion(versionless) = %q, want empty", got)
	}
}

// TestAffectingVulnerabilitiesLocalReplace is the core regression: an
// explicitly versioned local replace must not be silently dropped during
// version-range matching.
func TestAffectingVulnerabilitiesLocalReplace(t *testing.T) {
	mv := []*ModVulns{{
		Module: localReplaceModule(),
		Vulns:  []*osv.Entry{localTextVuln()},
	}}

	got := affectingVulnerabilities(mv, "", "")
	if len(got) != 1 {
		t.Fatalf("expected 1 module group, got %d", len(got))
	}
	if len(got[0].Vulns) != 1 {
		t.Fatalf("expected the advisory to survive version matching, got %d vulns", len(got[0].Vulns))
	}
	if got[0].Vulns[0].ID != "GO-LOCAL-0001" {
		t.Errorf("unexpected advisory %q", got[0].Vulns[0].ID)
	}
}

// TestForPackageSymbolLocalReplace ensures symbol-level conclusions still
// resolve against the real import path for a local replace.
func TestForPackageSymbolLocalReplace(t *testing.T) {
	aff := affectingVulns{{
		Module: localReplaceModule(),
		Vulns:  []*osv.Entry{localTextVuln()},
	}}

	pkgVulns := aff.ForPackage("golang.org/x/text", "golang.org/x/text/language")
	if len(pkgVulns) != 1 {
		t.Fatalf("ForPackage returned %d vulns, want 1", len(pkgVulns))
	}

	symVulns := aff.ForSymbol("golang.org/x/text", "golang.org/x/text/language", "Parse")
	if len(symVulns) != 1 {
		t.Fatalf("ForSymbol(Parse) returned %d vulns, want 1", len(symVulns))
	}

	// A symbol not named in the advisory must not match: reachability
	// precision is unchanged.
	if got := aff.ForSymbol("golang.org/x/text", "golang.org/x/text/language", "Other"); len(got) != 0 {
		t.Errorf("ForSymbol(Other) = %d vulns, want 0", len(got))
	}
}

// TestUnversionedLocalReplaceUnchanged locks in the existing conservative
// behavior for a filesystem replace whose go.mod requirement declares no
// version. That scenario is explicitly out of scope: the version is
// genuinely unknown, so no advisory is asserted.
func TestUnversionedLocalReplaceUnchanged(t *testing.T) {
	// Outer module has no declared version; the local replacement is
	// likewise versionless.
	versionlessLocal := &packages.Module{
		Path: "golang.org/x/text",
		Replace: &packages.Module{
			Path: "../localmods/x-text",
		},
	}

	if got := modVersion(versionlessLocal); got != "" {
		t.Errorf("modVersion(versionless local replace) = %q, want empty", got)
	}
	if got := modPath(versionlessLocal); got != "golang.org/x/text" {
		t.Errorf("modPath(versionless local replace) = %q, want golang.org/x/text", got)
	}

	// With no resolvable version, affected() keeps returning false so the
	// advisory is filtered out rather than producing a false positive.
	mv := []*ModVulns{{
		Module: versionlessLocal,
		Vulns:  []*osv.Entry{localTextVuln()},
	}}
	got := affectingVulnerabilities(mv, "", "")
	if len(got) != 1 || len(got[0].Vulns) != 0 {
		t.Fatalf("versionless local replace should keep 0 matched vulns, got %+v", got)
	}
}

// TestFetchVulnerabilitiesLocalReplace ensures advisories are queried under
// the original module path rather than the local filesystem path.
func TestFetchVulnerabilitiesLocalReplace(t *testing.T) {
	mc, err := client.NewInMemoryClient([]*osv.Entry{localTextVuln()})
	if err != nil {
		t.Fatal(err)
	}

	got, err := FetchVulnerabilities(context.Background(), mc, []*packages.Module{localReplaceModule()})
	if err != nil {
		t.Fatalf("FetchVulnerabilities failed: %s", err)
	}
	want := []*ModVulns{{
		Module: localReplaceModule(),
		Vulns:  []*osv.Entry{localTextVuln()},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("mismatch (-want, +got):\n%s", diff)
	}
}
