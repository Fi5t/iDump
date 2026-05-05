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
	"path/filepath"
	"strconv"
	"strings"

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
	remoteOutput   string
	remoteHost     string
	remotePort     int
	remoteUser     string
	remotePassword string
	remoteKey      string
)

var remoteCmd = &cobra.Command{
	Use:   "remote [flags] <target>",
	Short: "Decrypt and dump iOS app binaries to an IPA file via SSH/SFTP",
	Long: `remote connects to the device over SSH and downloads decrypted binaries via SFTP.

The Frida agent writes .fid files to the device; the host then retrieves them
over SFTP and assembles the final IPA.

Examples:
  idump remote com.example.App
  idump remote -H 192.168.1.10 -p 22 com.example.App
  idump remote -K ~/.ssh/id_rsa com.example.App`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		target := args[0]

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

		device, err := internal.GetUSBDevice(ctx)
		if err != nil {
			return err
		}

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

		ipaName := remoteOutput
		if ipaName == "" {
			ipaName = displayName
		}
		ipaName = strings.TrimSuffix(ipaName, ".ipa")

		return internal.StartDump(ctx, session, sftpClient, payloadPath, ".", ipaName)
	},
}

func init() {
	remoteCmd.Flags().StringVarP(&remoteOutput, "output", "o", "", "Output IPA filename (default: app display name)")
	remoteCmd.Flags().StringVarP(&remoteHost, "host", "H", defaultSSHHost, "SSH hostname")
	remoteCmd.Flags().IntVarP(&remotePort, "port", "p", defaultSSHPort, "SSH port")
	remoteCmd.Flags().StringVarP(&remoteUser, "user", "u", defaultSSHUser, "SSH username")
	remoteCmd.Flags().StringVarP(&remotePassword, "password", "P", defaultSSHPassword, "SSH password")
	remoteCmd.Flags().StringVarP(&remoteKey, "key", "K", "", "SSH private key file path")
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
