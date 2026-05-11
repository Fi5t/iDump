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
	"net"
	"os"
	"os/signal"
	"strconv"

	"github.com/Fi5t/idump/internal"
	"github.com/Fi5t/idump/internal/ui"
	"github.com/pkg/sftp"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSSHHost     = "localhost"
	defaultSSHPort     = 2222
	defaultSSHUser     = "root"
	defaultSSHPassword = "alpine"
)

var (
	remoteOutput     string
	remoteHost       string
	remotePort       int
	remoteUser       string
	remotePassword   string
	remoteKey        string
	remoteDodgeTier  string
	remoteEarly      string
	remoteDumpAll    bool
	remoteSkipSystem bool
	remoteFilter     string
	remoteOutputDir  string
)

var remoteCmd = &cobra.Command{
	Use:   "remote [flags] [target ...]",
	Short: "Decrypt and dump iOS app binaries to an IPA file via SSH/SFTP",
	Long: `remote connects to the device over SSH and downloads decrypted binaries via SFTP.

The Frida agent writes .fid files to the device; the host then retrieves them
over SFTP and assembles the final IPA.

Examples:
  idump remote com.example.App
  idump remote -H 192.168.1.10 -p 22 com.example.App
  idump remote -K ~/.ssh/id_rsa com.example.App
  idump remote com.app1 com.app2 com.app3
  idump remote --dump-all --skip-system -d ./ipa-out
  idump remote --dodge com.example.App
  idump remote --dodge=advanced com.example.App
  idump remote --early bypass.js com.example.App`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		bypassScript, err := resolveBypassScript(remoteDodgeTier, remoteEarly)
		if err != nil {
			return err
		}

		if remoteOutput != "" && (len(args) > 1 || remoteDumpAll) {
			return fmt.Errorf("--output cannot be used with multiple targets or --dump-all")
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		device, err := internal.GetUSBDevice(ctx)
		if err != nil {
			return err
		}

		if !remoteDumpAll && len(args) == 0 {
			return fmt.Errorf("target app required (name or bundle ID); use --dump-all to dump all apps")
		}

		sshClient, err := dialSSH(remoteHost, remotePort, remoteUser, remotePassword, remoteKey)
		if err != nil {
			return fmt.Errorf("SSH connection failed: %w\nCheck -H/--host and -p/--port flags", err)
		}
		defer func() { _ = sshClient.Close() }()

		sftpClient, err := sftp.NewClient(sshClient)
		if err != nil {
			return fmt.Errorf("SFTP client: %w", err)
		}
		defer func() { _ = sftpClient.Close() }()

		targets, err := resolveTargets(device, args, remoteDumpAll, remoteSkipSystem, remoteFilter)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return fmt.Errorf("no apps matched the given criteria")
		}

		ipaOverride, effectiveOutputDir := resolveOutputArgs(remoteOutput, remoteOutputDir)
		results := make([]DumpResult, 0, len(targets))
		for i, target := range targets {
			if len(targets) > 1 {
				ui.Step(fmt.Sprintf("[%d/%d] %s", i+1, len(targets), target))
			}
			r := dumpOne(ctx, device, target, bypassScript, effectiveOutputDir, ipaOverride, sftpClient)
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

func init() {
	remoteCmd.Flags().StringVarP(&remoteOutput, "output", "o", "", "Output IPA filename (default: app display name; single-app only)")
	remoteCmd.Flags().StringVarP(&remoteHost, "host", "H", defaultSSHHost, "SSH hostname")
	remoteCmd.Flags().IntVarP(&remotePort, "port", "p", defaultSSHPort, "SSH port")
	remoteCmd.Flags().StringVarP(&remoteUser, "user", "u", defaultSSHUser, "SSH username")
	remoteCmd.Flags().StringVarP(&remotePassword, "password", "P", defaultSSHPassword, "SSH password")
	remoteCmd.Flags().StringVarP(&remoteKey, "key", "K", "", "SSH private key file path")
	registerBypassFlags(remoteCmd, &remoteDodgeTier, &remoteEarly)
	registerBatchFlags(remoteCmd, &remoteDumpAll, &remoteSkipSystem, &remoteFilter, &remoteOutputDir)
	rootCmd.AddCommand(remoteCmd)
}

func dialSSH(host string, port int, user, password, keyFile string) (*ssh.Client, error) {
	var authMethods []ssh.AuthMethod

	if keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	authMethods = append(authMethods, ssh.Password(password))

	ui.Warn("SSH host key verification is disabled — ensure you trust the network")
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return ssh.Dial("tcp", addr, cfg)
}
