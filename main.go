// SPDX-License-Identifier: BSD-3-Clause

// authn-kinit gets a Kerberos TGT without a password and puts it in the
// Windows logon session, so that SMB (and anything else that speaks Kerberos)
// works from a machine that is not in a domain.
//
//	authn-kinit --issuer https://login.example.org --client kinit
//
// opens the login page of go-authn/bridge in the browser (RFC 8252 loopback
// flow, a passkey), asks bridge for a TGT for the person who logged in, and
// submits it to the Local Security Authority. Unattended, a machine holds a
// key pair instead (private_key_jwt, RFC 7523) and nobody is asked anything:
//
//	authn-kinit --issuer https://login.example.org --client winpc-17 --machine-key C:\ProgramData\authn\machine.key
//
// There is no password anywhere in it, and no way to add one.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// osExit is replaced by tests.
var osExit = os.Exit

func main() {
	if err := RootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "authn-kinit:", err)
		osExit(1)
	}
}

// RootCmd is the command, for tests to drive.
func RootCmd() *cobra.Command {
	var (
		issuer, client, machineKey, kid, credFile string
		noInject                                  bool
		timeout                                   time.Duration
	)
	root := &cobra.Command{
		Use:           "authn-kinit",
		Short:         "get a Kerberos TGT without a password, and load it into the Windows logon session",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if issuer == "" || client == "" {
				return errors.New("give --issuer and --client")
			}
			inject := !noInject && injectSupported
			if !inject && credFile == "" {
				return errors.New("nothing would be done with the ticket: this system cannot load one into a logon session (or --no-inject was given); give --cred-file")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			out := cmd.OutOrStdout()

			var access string
			var err error
			if machineKey != "" {
				access, err = machineToken(ctx, http.DefaultClient, issuer, client, machineKey, kid)
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "opening the login page in your browser...")
				access, err = interactiveToken(ctx, issuer, client)
			}
			if err != nil {
				return err
			}
			cred, err := fetchTGT(ctx, http.DefaultClient, issuer, access)
			if err != nil {
				return err
			}
			info, err := describeCred(cred, time.Now())
			if err != nil {
				return fmt.Errorf("the provider's ticket is unusable: %w", err)
			}
			if credFile != "" {
				if err := os.WriteFile(credFile, cred, 0o600); err != nil {
					return err
				}
				if err := os.Chmod(credFile, 0o600); err != nil {
					return err
				}
				fmt.Fprintf(out, "wrote %s\n", credFile)
			}
			if inject {
				if err := injectCred(cred); err != nil {
					return fmt.Errorf("loading the ticket into this logon session: %w", err)
				}
				fmt.Fprintln(out, "ticket loaded into this logon session")
			}
			fmt.Fprintf(out, "%s for %s@%s, until %s\n", info.Service, info.Client, info.Realm, info.End.Local().Format(time.RFC1123))
			return nil
		},
	}
	f := root.Flags()
	f.StringVar(&issuer, "issuer", "", "the provider, e.g. https://login.example.org (go-authn/bridge)")
	f.StringVar(&client, "client", "", "the client ID the provider knows this program by (a public client with kerberos_tickets; for a machine, its key client)")
	f.StringVar(&machineKey, "machine-key", "", "unattended: the machine's private key (PEM, PKCS#8, P-256 or Ed25519), instead of a login")
	f.StringVar(&kid, "kid", "", "with --machine-key: the key ID the provider registered it under")
	f.StringVar(&credFile, "cred-file", "", "also write the KRB-CRED (a .kirbi) here, mode 0600")
	f.BoolVar(&noInject, "no-inject", false, "do not load the ticket into the logon session (the default off Windows)")
	f.DurationVar(&timeout, "timeout", 5*time.Minute, "give up after this long")
	root.AddCommand(keygenCmd(), setupCmd())
	return root
}

// httpError reads a refusal's body, bounded, for a message.
func httpError(what string, resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
	return fmt.Errorf("%s: %s: %s", what, resp.Status, strings.TrimSpace(string(b)))
}
