package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/frida/frida-go/frida"
	"github.com/pkg/sftp"

	"github.com/Fi5t/idump/internal/ui"
)

type dumpState struct {
	mu        sync.Mutex
	once      sync.Once
	fileDict  map[string]string
	fileBytes map[string]int64
	done      chan struct{}
	err       chan error
	spinner   *spinner.Spinner
}

func StartDump(ctx context.Context, session *frida.Session, sftpClient *sftp.Client, payloadPath, outputDir, ipaName string) (err error) {
	defer func() {
		if derr := session.Detach(); err == nil && derr != nil {
			err = fmt.Errorf("detach session: %w", derr)
		}
	}()
	script, err := session.CreateScript(DumpJS)
	if err != nil {
		return fmt.Errorf("create script: %w", err)
	}

	spin := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
	spin.Suffix = " Injecting agent..."
	spin.Start()

	state := &dumpState{
		fileDict:  make(map[string]string),
		fileBytes: make(map[string]int64),
		done:      make(chan struct{}),
		err:       make(chan error, 1),
		spinner:   spin,
	}

	// msgCh decouples the Frida GLib callback thread from message processing.
	// The callback must return promptly so the GLib event loop stays free to
	// deliver other signals (notably "detached"). In SSH mode the handler does
	// blocking SFTP I/O, so without this the detach signal could never fire
	// while a download was in progress.
	// The GLib thread delivers messages one at a time (never re-enters until the
	// callback returns), so the channel is always filled in arrival order.
	msgCh := make(chan [2][]byte, 512)

	// Register BEFORE Load so frida-go's Load() sees hasHandler=true and skips
	// its internal connectClosure call — otherwise the signal fires twice per message.
	script.On("message", func(message string, data []byte) {
		select {
		case msgCh <- [2][]byte{[]byte(message), data}:
		default:
			select {
			case state.err <- errors.New("message queue overflow: agent sent too many messages"):
			default:
			}
		}
	})

	go func() {
		for {
			select {
			case pair, ok := <-msgCh:
				if !ok {
					return
				}
				if err := handleFridaMessage(string(pair[0]), pair[1], sftpClient, payloadPath, state); err != nil {
					select {
					case state.err <- err:
					default:
					}
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	session.On("detached", func(reason frida.SessionDetachReason, crash *frida.Crash) {
		select {
		case state.err <- fmt.Errorf("session detached: %s", reason):
		default:
		}
	})

	if err := script.Load(); err != nil {
		spin.Stop()
		return fmt.Errorf("load script: %w", err)
	}

	// USB mode: tell the script to send file contents through Frida messages.
	// SSH mode: script only sends paths; host downloads via SFTP.
	trigger := `"dump"`
	if sftpClient == nil {
		trigger = `{"mode":"usb"}`
	}
	script.Post(trigger, nil)

	select {
	case <-ctx.Done():
		spin.Stop()
		return fmt.Errorf("dump interrupted: %w", ctx.Err())
	case <-state.done:
	case jsErr := <-state.err:
		spin.Stop()
		return jsErr
	}

	spin.Suffix = " Creating IPA..."
	spin.Restart()

	if err := GenerateIPA(payloadPath, outputDir, ipaName, state.fileDict); err != nil {
		spin.Stop()
		return fmt.Errorf("generate IPA: %w", err)
	}

	spin.Stop()
	ipaPath := filepath.Join(outputDir, ipaName+".ipa")
	if info, statErr := os.Stat(ipaPath); statErr == nil {
		ui.OK(fmt.Sprintf("Saved %s (%s)", ipaPath, ui.FmtSize(info.Size())))
	}
	return nil
}

// Chunks must arrive in order.
func appendChunk(path string, data []byte, chunk int) (err error) {
	flag := os.O_WRONLY | os.O_CREATE
	if chunk == 0 {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_APPEND
	}
	f, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if _, werr := f.Write(data); werr != nil {
		return fmt.Errorf("write %s: %w", path, werr)
	}
	return nil
}

func intPayload(payload map[string]interface{}, key string, def int) int {
	if v, ok := payload[key].(float64); ok {
		return int(v)
	}
	return def
}

func strVal(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func handleFridaMessage(message string, data []byte, sftpClient *sftp.Client, payloadPath string, state *dumpState) error {
	var msg struct {
		Type        string                 `json:"type"`
		Payload     map[string]interface{} `json:"payload"`
		Description string                 `json:"description"`
		Stack       string                 `json:"stack"`
	}
	if err := json.Unmarshal([]byte(message), &msg); err != nil {
		return nil //nolint:nilerr // malformed Frida messages are silently skipped
	}
	if msg.Type == "error" {
		if msg.Stack != "" {
			ui.Warn("JS stack:\n" + msg.Stack)
		}
		jsErr := fmt.Errorf("frida script error: %s", msg.Description)
		select {
		case state.err <- jsErr:
		default:
		}
		return nil // error forwarded to state.err; return nil so the goroutine keeps running
	}
	if msg.Type != "send" || msg.Payload == nil {
		return nil
	}

	payload := msg.Payload

	if dumpVal, ok := payload["dump"]; ok {
		originPath := strVal(payload["path"])

		relPath := originPath
		if _, after, found := strings.Cut(originPath, ".app/"); found {
			relPath = after
		}

		if sftpClient == nil {
			basename := strVal(dumpVal)
			chunk := intPayload(payload, "chunk", 0)
			numChunks := intPayload(payload, "chunks", 1)
			totalSize := int64(intPayload(payload, "size", 0))
			localPath := filepath.Join(payloadPath, basename)
			state.mu.Lock()
			state.fileBytes[basename] += int64(len(data))
			received := state.fileBytes[basename]
			state.spinner.Suffix = fmt.Sprintf(" [%s / %s] %s", ui.FmtSize(received), ui.FmtSize(totalSize), basename)
			state.mu.Unlock()
			if err := appendChunk(localPath, data, chunk); err != nil {
				return fmt.Errorf("write %s chunk %d: %w", basename, chunk, err)
			}
			if chunk == numChunks-1 {
				state.mu.Lock()
				state.fileDict[basename] = relPath
				state.mu.Unlock()
			}
		} else {
			remotePath := strVal(dumpVal)
			localPath := filepath.Join(payloadPath, filepath.Base(remotePath))
			if err := sftpDownloadFile(sftpClient, remotePath, localPath, state.spinner); err != nil {
				return fmt.Errorf("download %s: %w", remotePath, err)
			}
			if err := os.Chmod(localPath, 0o644); err != nil { //nolint:gosec // payload file permissions
				ui.Warn(fmt.Sprintf("chmod %s: %v", localPath, err))
			}
			state.mu.Lock()
			state.fileDict[filepath.Base(remotePath)] = relPath
			state.mu.Unlock()
		}
	}

	if appFileVal, ok := payload["app_file"]; ok {
		relPath := strVal(appFileVal)
		appBaseName := strVal(payload["app"])
		chunk := intPayload(payload, "chunk", 0)
		numChunks := intPayload(payload, "chunks", 1)

		localPath := filepath.Join(payloadPath, appBaseName, relPath)
		if chunk == 0 {
			if err := os.MkdirAll(filepath.Dir(localPath), 0o750); err != nil {
				return fmt.Errorf("mkdir for app_file %s: %w", relPath, err)
			}
		}
		totalSize := int64(intPayload(payload, "size", 0))
		label := filepath.Join(appBaseName, relPath)
		state.mu.Lock()
		state.fileBytes[label] += int64(len(data))
		received := state.fileBytes[label]
		state.spinner.Suffix = fmt.Sprintf(" [%s / %s] %s", ui.FmtSize(received), ui.FmtSize(totalSize), label)
		state.mu.Unlock()
		if err := appendChunk(localPath, data, chunk); err != nil {
			return fmt.Errorf("write app_file %s chunk %d: %w", relPath, chunk, err)
		}

		if chunk == numChunks-1 {
			state.mu.Lock()
			state.fileDict["app"] = appBaseName
			state.mu.Unlock()
		}
		return nil
	}

	if appVal, ok := payload["app"]; ok && sftpClient != nil {
		remotePath := strVal(appVal)
		if err := sftpDownloadDir(sftpClient, remotePath, payloadPath, state.spinner); err != nil {
			return fmt.Errorf("download app dir %s: %w", remotePath, err)
		}
		chmodR(filepath.Join(payloadPath, filepath.Base(remotePath)), 0o750)
		state.mu.Lock()
		state.fileDict["app"] = filepath.Base(remotePath)
		state.mu.Unlock()
	}

	if _, ok := payload["done"]; ok {
		state.once.Do(func() { close(state.done) })
	}

	return nil
}

func sftpDownloadFile(client *sftp.Client, remotePath, localPath string, spin *spinner.Spinner) (err error) {
	rf, err := client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("sftp open %s: %w", remotePath, err)
	}
	defer func() { _ = rf.Close() }()

	lf, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", localPath, err)
	}
	defer func() {
		if cerr := lf.Close(); err == nil {
			err = cerr
		}
	}()

	name := filepath.Base(remotePath)
	var totalSize int64
	if stat, serr := rf.Stat(); serr == nil {
		totalSize = stat.Size()
	}
	spin.Suffix = fmt.Sprintf(" [0 B / %s] %s", ui.FmtSize(totalSize), name)
	if _, cerr := io.Copy(lf, &countingReader{r: rf, spin: spin, name: name, total: totalSize}); cerr != nil {
		err = fmt.Errorf("copy %s: %w", remotePath, cerr)
	}
	return err
}

type countingReader struct {
	r         io.Reader
	n         int64
	lastPrint int64
	total     int64
	spin      *spinner.Spinner
	name      string
}

func (cr *countingReader) Read(p []byte) (n int, err error) {
	n, err = cr.r.Read(p)
	cr.n += int64(n)
	if cr.n-cr.lastPrint >= 64*1024 || err == io.EOF {
		cr.spin.Suffix = fmt.Sprintf(" [%s / %s] %s", ui.FmtSize(cr.n), ui.FmtSize(cr.total), cr.name)
		cr.lastPrint = cr.n
	}
	return
}

func sftpDownloadDir(client *sftp.Client, remotePath, localBase string, spin *spinner.Spinner) error {
	return sftpDownloadDirVisited(client, remotePath, localBase, spin, make(map[string]bool))
}

// visited tracks resolved symlink targets to break cycles.
func sftpDownloadDirVisited(client *sftp.Client, remotePath, localBase string, spin *spinner.Spinner, visited map[string]bool) error {
	walker := client.Walk(remotePath)
	remoteParent := filepath.Dir(remotePath)

	var errs []error
	for walker.Step() {
		if err := walker.Err(); err != nil {
			ui.Warn(fmt.Sprintf("walk warning at %s: %v", walker.Path(), err))
			continue
		}

		walkerPath := walker.Path()
		stat := walker.Stat()

		rel, err := filepath.Rel(remoteParent, walkerPath)
		if err != nil {
			continue
		}
		localDst := filepath.Join(localBase, rel)

		// sftp.Walk uses lstat, so symlinks are not followed automatically.
		if stat.Mode()&os.ModeSymlink != 0 {
			if err := sftpHandleSymlink(client, walkerPath, localDst, spin, visited); err != nil {
				errs = append(errs, err)
			}
			continue
		}

		if stat.IsDir() {
			if err := os.MkdirAll(localDst, 0o750); err != nil {
				return fmt.Errorf("mkdir %s: %w", localDst, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(localDst), 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(localDst), err)
		}
		if err := sftpDownloadFile(client, walkerPath, localDst, spin); err != nil {
			errs = append(errs, fmt.Errorf("download %s: %w", walkerPath, err))
		}
	}
	return errors.Join(errs...)
}

func sftpHandleSymlink(client *sftp.Client, remotePath, localDst string, spin *spinner.Spinner, visited map[string]bool) error {
	target, err := client.ReadLink(remotePath)
	if err != nil {
		return fmt.Errorf("readlink %s: %w", remotePath, err)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(remotePath), target)
	}
	if visited[target] {
		return nil
	}

	targetInfo, err := client.Stat(target)
	if err != nil {
		return fmt.Errorf("stat symlink target %s: %w", target, err)
	}

	if targetInfo.IsDir() {
		visited[target] = true
		if err := os.MkdirAll(localDst, 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", localDst, err)
		}
		return sftpDownloadDirContents(client, target, localDst, spin, visited)
	}
	if err := os.MkdirAll(filepath.Dir(localDst), 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(localDst), err)
	}
	if err := sftpDownloadFile(client, target, localDst, spin); err != nil {
		return fmt.Errorf("download symlink target %s: %w", target, err)
	}
	return nil
}

// sftpDownloadDirContents downloads the contents of remoteSrc directly into
// localDst (entries appear at localDst/<name>, not localDst/<basename>/<name>).
// Used to materialise symlinked directories in place.
func sftpDownloadDirContents(client *sftp.Client, remoteSrc, localDst string, spin *spinner.Spinner, visited map[string]bool) error {
	entries, err := client.ReadDir(remoteSrc)
	if err != nil {
		return fmt.Errorf("readdir %s: %w", remoteSrc, err)
	}

	var errs []error
	for _, entry := range entries {
		entryRemote := filepath.Join(remoteSrc, entry.Name())
		entryLocal := filepath.Join(localDst, entry.Name())

		if entry.Mode()&os.ModeSymlink != 0 {
			if err := sftpHandleSymlink(client, entryRemote, entryLocal, spin, visited); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if entry.IsDir() {
			if err := os.MkdirAll(entryLocal, 0o750); err != nil {
				return fmt.Errorf("mkdir %s: %w", entryLocal, err)
			}
			if err := sftpDownloadDirContents(client, entryRemote, entryLocal, spin, visited); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := sftpDownloadFile(client, entryRemote, entryLocal, spin); err != nil {
			errs = append(errs, fmt.Errorf("download %s: %w", entryRemote, err))
		}
	}
	return errors.Join(errs...)
}

func chmodR(path string, mode os.FileMode) {
	if err := filepath.WalkDir(path, func(p string, _ fs.DirEntry, walkErr error) error {
		if walkErr == nil {
			if cerr := os.Chmod(p, mode); cerr != nil { //nolint:gosec // controlled local temp directory
				ui.Warn(fmt.Sprintf("chmod %s: %v", p, cerr))
			}
		}
		return nil
	}); err != nil {
		ui.Warn(fmt.Sprintf("chmodR %s: %v", path, err))
	}
}
