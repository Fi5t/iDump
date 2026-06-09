package cmd

import (
	"testing"
)

func TestResolveOutputArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		outputFlag string
		defaultDir string
		wantIPA    string
		wantDir    string
	}{
		{
			name:       "empty flag keeps defaults",
			outputFlag: "",
			defaultDir: "/default",
			wantIPA:    "",
			wantDir:    "/default",
		},
		{
			name:       "filename only keeps default dir",
			outputFlag: "out.ipa",
			defaultDir: "/default",
			wantIPA:    "out",
			wantDir:    "/default",
		},
		{
			name:       "absolute path overrides dir",
			outputFlag: "/custom/path/out.ipa",
			defaultDir: "/default",
			wantIPA:    "out",
			wantDir:    "/custom/path",
		},
		{
			name:       "no ipa extension preserved",
			outputFlag: "myapp",
			defaultDir: ".",
			wantIPA:    "myapp",
			wantDir:    ".",
		},
		{
			name:       "relative path with dir",
			outputFlag: "builds/app.ipa",
			defaultDir: "/default",
			wantIPA:    "app",
			wantDir:    "builds",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotIPA, gotDir := resolveOutputArgs(tc.outputFlag, tc.defaultDir)
			if gotIPA != tc.wantIPA {
				t.Errorf("ipaOverride = %q, want %q", gotIPA, tc.wantIPA)
			}
			if gotDir != tc.wantDir {
				t.Errorf("effectiveDir = %q, want %q", gotDir, tc.wantDir)
			}
		})
	}
}
