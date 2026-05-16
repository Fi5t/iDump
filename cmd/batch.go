package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Fi5t/idump/internal"
	"github.com/Fi5t/idump/internal/ui"
	"github.com/frida/frida-go/frida"
	"github.com/pkg/sftp"
	"github.com/spf13/cobra"
)

// DumpResult holds the outcome of a single-app dump attempt.
type DumpResult struct {
	Target      string
	DisplayName string
	IPAPath     string
	Err         error
}

// ipaOverride renames the output IPA; pass "" to use the app display name.
func dumpOne(
	ctx context.Context,
	device frida.DeviceInt,
	target string,
	bypassScript string,
	outputDir string,
	ipaOverride string,
	sftpClient *sftp.Client,
) DumpResult {
	baseDir, err := os.MkdirTemp("", "idump-payload-*")
	if err != nil {
		return DumpResult{Target: target, Err: fmt.Errorf("temp dir: %w", err)}
	}
	defer func() { _ = os.RemoveAll(baseDir) }()

	payloadPath := filepath.Join(baseDir, "Payload")
	if err := os.MkdirAll(payloadPath, 0o750); err != nil {
		return DumpResult{Target: target, Err: fmt.Errorf("mkdir payload: %w", err)}
	}

	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return DumpResult{Target: target, Err: fmt.Errorf("output dir: %w", err)}
	}
	if abs, err := filepath.Abs(outputDir); err == nil {
		outputDir = abs
	}

	session, displayName, err := internal.OpenApp(ctx, device, target, bypassScript)
	if err != nil {
		return DumpResult{Target: target, Err: err}
	}

	ipaName := displayName
	if ipaOverride != "" {
		ipaName = ipaOverride
	}

	if err := internal.StartDump(ctx, session, sftpClient, payloadPath, outputDir, ipaName); err != nil {
		return DumpResult{Target: target, DisplayName: displayName, Err: err}
	}

	return DumpResult{
		Target:      target,
		DisplayName: displayName,
		IPAPath:     filepath.Join(outputDir, ipaName+".ipa"),
	}
}

// When dumpAll is false it returns args unchanged.
func resolveTargets(
	device frida.DeviceInt,
	args []string,
	dumpAll bool,
	skipSystem bool,
	filter string,
) ([]string, error) {
	if !dumpAll {
		return args, nil
	}
	apps, err := internal.GetApplications(device)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, a := range apps {
		id := a.Identifier()
		if skipSystem && strings.HasPrefix(id, "com.apple.") {
			continue
		}
		if filter != "" && !strings.Contains(id, filter) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func printSummary(results []DumpResult) {
	if len(results) <= 1 {
		return
	}

	nameW := len("Name")
	fileW := len("File")
	for _, r := range results {
		label := r.DisplayName
		if label == "" {
			label = r.Target
		}
		if len(label) > nameW {
			nameW = len(label)
		}
		if r.IPAPath != "" {
			f := filepath.Base(r.IPAPath)
			if len(f) > fileW {
				fileW = len(f)
			}
		}
	}
	idxW := len(strconv.Itoa(len(results)))
	statusW := len("✗ failed")

	fmt.Println()
	fmt.Printf("  %*s  %-*s  %-*s  %s\n",
		idxW, "#",
		nameW, "Name",
		statusW, "Status",
		"File / Note")
	sep := strings.Repeat("─", idxW+2+nameW+2+statusW+2+max(fileW, len("File / Note")))
	fmt.Println("  " + sep)

	var succeeded, failed int
	for i, r := range results {
		label := r.DisplayName
		if label == "" {
			label = r.Target
		}
		var status, note string
		if r.Err != nil {
			failed++
			status = "✗ failed"
			note = r.Err.Error()
		} else {
			succeeded++
			status = "✓"
			note = filepath.Base(r.IPAPath)
			if info, err := os.Stat(r.IPAPath); err == nil {
				note += " (" + ui.FmtSize(info.Size()) + ")"
			}
		}
		fmt.Printf("  %*d  %-*s  %-*s  %s\n",
			idxW, i+1,
			nameW, label,
			statusW, status,
			note)
	}

	fmt.Println("  " + sep)
	fmt.Printf("  %d processed · %d succeeded · %d failed\n\n",
		len(results), succeeded, failed)

	if failed > 0 {
		ui.Warn("failed apps can be retried individually, optionally with --dodge or --dodge=advanced")
	}
}

func resolveOutputArgs(outputFlag, defaultDir string) (ipaOverride, effectiveDir string) {
	effectiveDir = defaultDir
	if outputFlag == "" {
		return
	}
	ipaOverride = strings.TrimSuffix(filepath.Base(outputFlag), ".ipa")
	if dir := filepath.Dir(outputFlag); dir != "." {
		effectiveDir = dir
	}
	return
}

func registerBatchFlags(cmd *cobra.Command, dumpAll, skipSystem *bool, filter, outputDir *string) {
	cmd.Flags().BoolVarP(dumpAll, "dump-all", "a", false, "Dump all installed apps")
	cmd.Flags().BoolVar(skipSystem, "skip-system", false, "Skip com.apple.* apps (use with --dump-all)")
	cmd.Flags().StringVar(filter, "filter", "", "Include only apps whose bundle ID contains this string (use with --dump-all)")
	cmd.Flags().StringVarP(outputDir, "output-dir", "d", ".", "Directory to save IPA files")
}
