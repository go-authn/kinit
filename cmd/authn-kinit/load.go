// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// loadCmd loads a KRB-CRED that is already a file (written by --cred-file,
// here or elsewhere) into the logon session: the same checks, the same call.
func loadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "load FILE",
		Short: "load a KRB-CRED (.kirbi) file into this logon session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !injectSupported {
				return errors.New("loading a ticket into a logon session is Windows only")
			}
			b, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			info, err := describeCred(b, time.Now())
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			if err := injectCred(b); err != nil {
				return fmt.Errorf("loading the ticket into this logon session: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ticket loaded: %s for %s@%s, until %s\n", info.Service, info.Client, info.Realm, info.End.Local().Format(time.RFC1123))
			return nil
		},
	}
}
