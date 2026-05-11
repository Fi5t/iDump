package internal

import (
	"archive/zip"
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
		return fmt.Errorf("app bundle name not found in file dict")
	}

	for key, relPath := range fileDict {
		if key == "app" {
			continue
		}
		src := filepath.Join(payloadPath, key)
		dst := filepath.Join(payloadPath, appName, relPath)

		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
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
		return err
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
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}

		if d.IsDir() {
			hdr := &zip.FileHeader{
				Name:   rel + "/",
				Method: zip.Store,
			}
			hdr.SetMode(0o755 | fs.ModeDir)
			if _, err = w.CreateHeader(hdr); err != nil {
				return err
			}
			return nil
		}

		fw, err := w.Create(rel)
		if err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = src.Close() }()
		_, err = io.Copy(fw, src)
		return err
	})
}

func fmtSize(b int64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
