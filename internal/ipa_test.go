package internal

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateIPA_CreatesValidZip(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	payloadPath := filepath.Join(tmpDir, "Payload")
	outputDir := t.TempDir()

	appDir := filepath.Join(payloadPath, "MyApp.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "Info.plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payloadPath, "MyApp"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	fileDict := map[string]string{
		"app":   "MyApp.app",
		"MyApp": "MyApp",
	}

	const ipaName = "test_generate_ipa"
	if err := GenerateIPA(payloadPath, outputDir, ipaName, fileDict); err != nil {
		t.Fatalf("GenerateIPA: %v", err)
	}

	zr, err := zip.OpenReader(filepath.Join(outputDir, ipaName+".ipa"))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer zr.Close()

	got := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		got[f.Name] = true
	}

	for _, want := range []string{
		"Payload/MyApp.app/",
		"Payload/MyApp.app/Info.plist",
		"Payload/MyApp.app/MyApp",
	} {
		if !got[want] {
			t.Errorf("zip missing %q; entries: %v", want, got)
		}
	}
}

func TestGenerateIPA_MissingAppKey(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	payloadPath := filepath.Join(tmpDir, "Payload")
	if err := os.MkdirAll(payloadPath, 0o755); err != nil {
		t.Fatal(err)
	}

	err := GenerateIPA(payloadPath, t.TempDir(), "out", map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing 'app' key in fileDict")
	}
}

func TestGenerateIPA_PayloadPreservedAfterSuccess(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	payloadPath := filepath.Join(tmpDir, "Payload")
	appDir := filepath.Join(payloadPath, "App.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "Info.plist"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	outputDir := t.TempDir()
	if err := GenerateIPA(payloadPath, outputDir, "test_cleanup_ipa", map[string]string{"app": "App.app"}); err != nil {
		t.Fatalf("GenerateIPA: %v", err)
	}

	if _, err := os.Stat(payloadPath); os.IsNotExist(err) {
		t.Errorf("payloadPath should NOT be removed by GenerateIPA — cleanup is caller's responsibility")
	}

	if _, err := os.Stat(filepath.Join(outputDir, "test_cleanup_ipa.ipa")); err != nil {
		t.Errorf("expected IPA file in outputDir: %v", err)
	}
}
