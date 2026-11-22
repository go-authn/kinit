// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// keygenCmd makes a machine key: a P-256 private key (PKCS#8 PEM, mode 0600,
// never overwritten) and the JWK Set to put in the provider's client block
// (bridge: jwks_file). The private key never leaves the machine.
func keygenCmd() *cobra.Command {
	var out, kid string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "make a machine key, and print the public JWK Set to register at the provider",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" || kid == "" {
				return errors.New("give --out and --kid")
			}
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			der, err := x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				return err
			}
			// O_EXCL: a key that is already there is somebody's credential.
			f, err := createExclusive(out) // 0600; on Windows a protected owner-only DACL
			if err != nil {
				return err
			}
			if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			jwks, err := publicJWKS(k, "ES256", kid)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s (keep it on this machine; restrict it to the account that runs authn-kinit)\n", out)
			fmt.Fprintf(cmd.ErrOrStderr(), "register this public key at the provider (bridge client block: jwks_file):\n")
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", jwks)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "where to write the private key")
	cmd.Flags().StringVar(&kid, "kid", "", "the key ID to register it under")
	return cmd
}
