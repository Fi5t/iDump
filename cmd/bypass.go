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
	"errors"
	"fmt"

	"github.com/Fi5t/idump/internal"
	"github.com/spf13/cobra"
)

const (
	bypassTierBasic    = "basic"
	bypassTierAdvanced = "advanced"
)

func resolveBypassScript(tier, earlyPath string) (string, error) {
	if tier != "" && tier != bypassTierBasic && tier != bypassTierAdvanced {
		return "", fmt.Errorf("--dodge: unknown tier %q (use %q or %q)", tier, bypassTierBasic, bypassTierAdvanced)
	}
	if tier != "" && earlyPath != "" {
		return "", errors.New("--dodge and --early are mutually exclusive")
	}
	switch tier {
	case bypassTierAdvanced:
		return internal.AdvancedBypassJS, nil
	case bypassTierBasic:
		return internal.BypassJS, nil
	}
	if earlyPath != "" {
		s, err := internal.CompileOrLoad(earlyPath)
		if err != nil {
			return "", fmt.Errorf("bypass script: %w", err)
		}
		return s, nil
	}
	return "", nil
}

func registerBypassFlags(cmd *cobra.Command, tier, early *string) {
	cmd.Flags().StringVar(tier, "dodge", "", `Bypass tier: "basic" (libc hooks) or "advanced" (advanced kernel bypass); bare --dodge uses "basic"`)
	cmd.Flag("dodge").NoOptDefVal = bypassTierBasic
	cmd.Flags().StringVar(early, "early", "", "Path to custom bypass script (.js or .ts); mutually exclusive with --dodge")
}
