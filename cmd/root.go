/*
Copyright © 2026 Fi5t

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/Fi5t/idump/internal"
	"github.com/Fi5t/idump/internal/ui"
	"github.com/spf13/cobra"
)

var (
	listApps   bool
	outputIPA  string
	dodgeTier  string
	earlyPath  string
	dumpAll    bool
	skipSystem bool
	filter     string
	outputDir  string
)

var rootCmd = &cobra.Command{
	SilenceUsage: true,
	Use:          "idump [flags] [target ...]",
	Short:        "Decrypt and dump iOS app binaries to an IPA file via USB",
	Args:         cobra.ArbitraryArgs,
	Long: `idump decrypts and dumps iOS app binaries from a USB-connected device using Frida.

File contents are transferred directly through Frida messages — no SSH required.

Examples:
  idump -l                               List installed apps
  idump com.example.App                  Dump by bundle ID
  idump "My App"                         Dump by display name
  idump -o output.ipa com.example.App    Dump with custom output name
  idump com.app1 com.app2 com.app3       Dump multiple apps
  idump --dump-all -d ./ipa-out          Dump all apps to ./ipa-out
  idump --dump-all --skip-system         Dump non-Apple apps
  idump --dump-all --filter com.myco.    Dump apps matching bundle ID prefix
  idump --dodge com.example.App          Dump with basic anti-Frida bypass
  idump --dodge=advanced com.example.App Dump with advanced bypass (hardened apps)
  idump --early bypass.js com.example.App  Dump with custom bypass script
  idump remote --help                    Dump via SSH/SFTP instead`,
	RunE: func(cmd *cobra.Command, args []string) error {
		bypassScript, err := resolveBypassScript(dodgeTier, earlyPath)
		if err != nil {
			return err
		}

		if outputIPA != "" && (len(args) > 1 || dumpAll) {
			return errors.New("--output cannot be used with multiple targets or --dump-all")
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		device, err := internal.GetUSBDevice(ctx)
		if err != nil {
			return err
		}

		if listApps {
			return internal.ListApplications(device)
		}

		if !dumpAll && len(args) == 0 {
			return errors.New("target app required (name or bundle ID); use -l to list or --dump-all")
		}

		targets, err := resolveTargets(device, args, dumpAll, skipSystem, filter)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return errors.New("no apps matched the given criteria")
		}

		ipaOverride, effectiveOutputDir := resolveOutputArgs(outputIPA, outputDir)
		results := make([]DumpResult, 0, len(targets))
		for i, target := range targets {
			if len(targets) > 1 {
				ui.Step(fmt.Sprintf("[%d/%d] %s", i+1, len(targets), target))
			}
			r := dumpOne(ctx, device, target, bypassScript, effectiveOutputDir, ipaOverride, nil)
			results = append(results, r)
			if r.Err != nil {
				ui.Err(r.Err.Error())
			}
		}

		printSummary(results)

		for _, r := range results {
			if r.Err != nil {
				return r.Err
			}
		}
		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVarP(&listApps, "list", "l", false, "List installed apps")
	rootCmd.Flags().StringVarP(&outputIPA, "output", "o", "", "Output IPA filename (default: app display name; single-app only)")
	registerBypassFlags(rootCmd, &dodgeTier, &earlyPath)
	registerBatchFlags(rootCmd, &dumpAll, &skipSystem, &filter, &outputDir)
}
