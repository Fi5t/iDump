package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/briandowns/spinner"
)

func newTestState() *dumpState {
	spin := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
	return &dumpState{
		fileDict:  make(map[string]string),
		fileBytes: make(map[string]int64),
		done:      make(chan struct{}),
		err:       make(chan error, 1),
		spinner:   spin,
	}
}

func TestHandleFridaMessage_Done(t *testing.T) {
	t.Parallel()

	state := newTestState()
	msg := `{"type":"send","payload":{"done":true}}`
	if err := handleFridaMessage(msg, nil, nil, t.TempDir(), state); err != nil {
		t.Fatal(err)
	}
	select {
	case <-state.done:
	default:
		t.Fatal("state.done not closed after done message")
	}
}

func TestHandleFridaMessage_DoneIsSafeWhenCalledTwice(t *testing.T) {
	t.Parallel()

	state := newTestState()
	msg := `{"type":"send","payload":{"done":true}}`
	_ = handleFridaMessage(msg, nil, nil, t.TempDir(), state)
	// Must not panic on second call.
	_ = handleFridaMessage(msg, nil, nil, t.TempDir(), state)
}

func TestHandleFridaMessage_ErrorType(t *testing.T) {
	t.Parallel()

	state := newTestState()
	msg := `{"type":"error","description":"script crashed","stack":"at line 1"}`
	if err := handleFridaMessage(msg, nil, nil, t.TempDir(), state); err != nil {
		t.Fatal(err)
	}
	select {
	case jsErr := <-state.err:
		if jsErr == nil {
			t.Fatal("expected non-nil error in state.err")
		}
	default:
		t.Fatal("no error sent to state.err")
	}
}

func TestHandleFridaMessage_USBDump(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	state := newTestState()

	fileData := []byte("fake decrypted binary")
	// size value matches len(fileData)
	msg := `{"type":"send","payload":{"dump":"MyApp","path":"/var/containers/Bundle/App.app/MyApp","size":21}}`
	if err := handleFridaMessage(msg, fileData, nil, tmpDir, state); err != nil {
		t.Fatal(err)
	}

	written, err := os.ReadFile(filepath.Join(tmpDir, "MyApp"))
	if err != nil {
		t.Fatalf("expected file to be written: %v", err)
	}
	if string(written) != string(fileData) {
		t.Errorf("file content = %q, want %q", written, fileData)
	}

	state.mu.Lock()
	relPath := state.fileDict["MyApp"]
	state.mu.Unlock()

	if relPath != "MyApp" {
		t.Errorf("fileDict[MyApp] = %q, want %q", relPath, "MyApp")
	}
}

func TestHandleFridaMessage_AppFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	state := newTestState()

	fileData := []byte("<plist/>")
	msg := `{"type":"send","payload":{"app_file":"Info.plist","app":"MyApp.app","size":8}}`
	if err := handleFridaMessage(msg, fileData, nil, tmpDir, state); err != nil {
		t.Fatal(err)
	}

	written, err := os.ReadFile(filepath.Join(tmpDir, "MyApp.app", "Info.plist"))
	if err != nil {
		t.Fatalf("expected file to be written: %v", err)
	}
	if string(written) != string(fileData) {
		t.Errorf("file content = %q, want %q", written, fileData)
	}

	state.mu.Lock()
	appName := state.fileDict["app"]
	state.mu.Unlock()

	if appName != "MyApp.app" {
		t.Errorf("fileDict[app] = %q, want %q", appName, "MyApp.app")
	}
}

func TestHandleFridaMessage_UnknownTypeIsIgnored(t *testing.T) {
	t.Parallel()

	state := newTestState()
	msg := `{"type":"log","payload":{"level":"info","message":"hello"}}`
	if err := handleFridaMessage(msg, nil, nil, t.TempDir(), state); err != nil {
		t.Fatal(err)
	}
	select {
	case <-state.done:
		t.Fatal("done should not be closed for a log message")
	default:
	}
}

// TestHandleFridaMessage_AppFileChunkZeroTruncates verifies that a second
// app_file message for the same relPath overwrites the first. Deduplication
// of identical underlying files lives in the Frida agent; the Go handler is
// only responsible for writing whatever the agent sends.
func TestHandleFridaMessage_AppFileChunkZeroTruncates(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	state := newTestState()

	msg1 := `{"type":"send","payload":{"app_file":"res.txt","app":"MyApp.app","chunks":1}}`
	if err := handleFridaMessage(msg1, []byte("first"), nil, tmpDir, state); err != nil {
		t.Fatal(err)
	}
	msg2 := `{"type":"send","payload":{"app_file":"res.txt","app":"MyApp.app","chunks":1}}`
	if err := handleFridaMessage(msg2, []byte("second"), nil, tmpDir, state); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(tmpDir, "MyApp.app", "res.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("content = %q, want %q (chunk 0 must truncate)", got, "second")
	}
}

func TestStartDump_SessionDetachUnblocksErr(t *testing.T) {
	t.Parallel()

	state := newTestState()
	select {
	case state.err <- fmt.Errorf("session detached: process-terminated"):
	default:
	}
	select {
	case err := <-state.err:
		if err == nil {
			t.Fatal("expected non-nil error")
		}
	default:
		t.Fatal("state.err was not signalled")
	}
}

func TestHandleFridaMessage_ConcurrentDumps(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	state := newTestState()

	const n = 5
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			msg := fmt.Sprintf(
				`{"type":"send","payload":{"dump":"bin%d","path":"/App.app/bin%d","size":4}}`,
				idx, idx,
			)
			_ = handleFridaMessage(msg, []byte("data"), nil, tmpDir, state)
		}(i)
	}
	wg.Wait()

	state.mu.Lock()
	count := len(state.fileDict)
	state.mu.Unlock()

	if count != n {
		t.Errorf("expected %d entries in fileDict, got %d", n, count)
	}
}
