package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Fi5t/idump/internal"
)

func TestResolveBypassScript(t *testing.T) {
	t.Parallel()

	jsFile := filepath.Join(t.TempDir(), "bypass.js")
	if err := os.WriteFile(jsFile, []byte("// custom bypass"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		tier       string
		earlyPath  string
		wantErr    bool
		wantScript string
	}{
		{"no flags", "", "", false, ""},
		{"basic tier", "basic", "", false, internal.BypassJS},
		{"advanced tier", "advanced", "", false, internal.AdvancedBypassJS},
		{"unknown tier", "unknown", "", true, ""},
		{"dodge and early mutually exclusive", "basic", jsFile, true, ""},
		{"early js file", "", jsFile, false, "// custom bypass"},
		{"early nonexistent file", "", "nonexistent.js", true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveBypassScript(tc.tier, tc.earlyPath)
			if (err != nil) != tc.wantErr {
				t.Fatalf("resolveBypassScript(%q, %q) error = %v, wantErr %v", tc.tier, tc.earlyPath, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.wantScript {
				t.Errorf("resolveBypassScript(%q, %q) = %q, want %q", tc.tier, tc.earlyPath, got, tc.wantScript)
			}
		})
	}
}
