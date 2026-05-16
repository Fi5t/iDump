package internal

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func GenerateIPA(payloadPath, outputDir, ipaName string, fileDict map[string]string) error {
	ipaFilename := ipaName + ".ipa"

	appName, ok := fileDict["app"]
	if !ok {
		return errors.New("app bundle name not found in file dict")
	}

	for key, relPath := range fileDict {
		if key == "app" {
			continue
		}
		src := filepath.Join(payloadPath, key)
		dst := filepath.Join(payloadPath, appName, relPath)

		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return fmt.Errorf("mkdir for %s: %w", dst, err)
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("move %s → %s: %w", src, dst, err)
		}
	}

	zipPath := filepath.Join(outputDir, ipaFilename)
	if err := zipDir(filepath.Dir(payloadPath), "Payload", zipPath); err != nil {
		return fmt.Errorf("zip: %w", err)
	}

	return nil
}

func zipDir(baseDir, subDir, destZip string) (err error) {
	f, err := os.Create(destZip)
	if err != nil {
		return fmt.Errorf("create zip %s: %w", destZip, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

	w := zip.NewWriter(f)
	defer func() {
		if cerr := w.Close(); err == nil {
			err = cerr
		}
	}()

	root := filepath.Join(baseDir, subDir)
	if werr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(baseDir, path)
		if relErr != nil {
			return fmt.Errorf("rel path for %s: %w", path, relErr)
		}

		if d.IsDir() {
			hdr := &zip.FileHeader{
				Name:   rel + "/",
				Method: zip.Store,
			}
			hdr.SetMode(0o755 | fs.ModeDir)
			if _, hErr := w.CreateHeader(hdr); hErr != nil {
				return fmt.Errorf("zip header for %s: %w", rel, hErr)
			}
			return nil
		}

		fw, fwErr := w.Create(rel)
		if fwErr != nil {
			return fmt.Errorf("zip entry for %s: %w", rel, fwErr)
		}
		src, srcErr := os.Open(path) //nolint:gosec // walking a controlled local temp directory
		if srcErr != nil {
			return fmt.Errorf("open %s: %w", path, srcErr)
		}
		_, cpErr := io.Copy(fw, src)
		_ = src.Close()
		if cpErr != nil {
			return fmt.Errorf("copy %s: %w", path, cpErr)
		}
		return nil
	}); werr != nil {
		return fmt.Errorf("walk %s: %w", root, werr)
	}
	return nil
}
