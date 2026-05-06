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
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/Fi5t/idump/internal"
	"github.com/spf13/cobra"
)

var (
	listApps  bool
	outputIPA string
)

var rootCmd = &cobra.Command{
	SilenceUsage: true,
	Use:          "idump [flags] [target]",
	Short:        "Decrypt and dump iOS app binaries to an IPA file via USB",
	Args:         cobra.ArbitraryArgs,
	Long: `idump decrypts and dumps iOS app binaries from a USB-connected device using Frida.

File contents are transferred directly through Frida messages — no SSH required.

Examples:
  idump -l                          List installed apps
  idump com.example.App             Dump by bundle ID
  idump "My App"                    Dump by display name
  idump -o output.ipa com.example.App  Dump with custom output name
  idump remote --help               Dump via SSH/SFTP instead`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		device, err := internal.GetUSBDevice(ctx)
		if err != nil {
			return err
		}

		if listApps {
			return internal.ListApplications(device)
		}

		if len(args) == 0 {
			return fmt.Errorf("target app required (name or bundle ID); use -l to list apps")
		}
		target := args[0]

		baseDir, err := os.MkdirTemp("", "idump-payload-*")
		if err != nil {
			return fmt.Errorf("temp dir: %w", err)
		}
		defer func() { _ = os.RemoveAll(baseDir) }()
		payloadPath := filepath.Join(baseDir, "Payload")
		if err := os.MkdirAll(payloadPath, 0o755); err != nil {
			return fmt.Errorf("mkdir payload: %w", err)
		}

		session, displayName, _, err := internal.OpenTargetApp(ctx, device, target)
		if err != nil {
			return err
		}

		ipaName := outputIPA
		if ipaName == "" {
			ipaName = displayName
		}
		ipaName = strings.TrimSuffix(ipaName, ".ipa")

		return internal.StartDump(ctx, session, nil, payloadPath, ".", ipaName)
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
	rootCmd.Flags().StringVarP(&outputIPA, "output", "o", "", "Output IPA filename (default: app display name)")
}
