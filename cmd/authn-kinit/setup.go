// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// The one-time administrator setup of a non-domain Windows machine: tell the
// Kerberos package where the realm's KDC is, and which hosts belong to the
// realm (so that a share named fs.example.org asks THAT KDC for cifs/fs...).
// ksetup is Microsoft's tool for exactly this ("initializes the registry keys
// that the Kerberos SSP uses to locate a KDC ... if the computer is not a
// member of a Windows domain", ksetup, Windows Commands).

var (
	realmRe = regexp.MustCompile(`^[A-Z0-9]([A-Z0-9.-]{0,253}[A-Z0-9])?$`)
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`)
)

// ksetupPlan is the ksetup invocations that set a machine up (or take it down
// again), each one a program and its arguments: never a shell line, so that a
// name cannot become a command.
func ksetupPlan(realm, kdc string, hosts []string, remove bool) ([][]string, error) {
	if !realmRe.MatchString(realm) {
		return nil, fmt.Errorf("realm %q: capital letters, digits, dots and hyphens (e.g. EXAMPLE.ORG)", realm)
	}
	if !hostRe.MatchString(kdc) {
		return nil, fmt.Errorf("kdc %q: a host name", kdc)
	}
	if len(hosts) == 0 {
		return nil, errors.New("give at least one --host: the file server's name, as people type it")
	}
	add, del := "/addhosttorealmmap", "/delhosttorealmmap"
	kdcAdd, kdcDel := "/addkdc", "/delkdc"
	var plan [][]string
	if remove {
		for _, h := range hosts {
			if !hostRe.MatchString(h) {
				return nil, fmt.Errorf("host %q: a host name", h)
			}
			plan = append(plan, []string{"ksetup", del, h, realm})
		}
		return append(plan, []string{"ksetup", kdcDel, realm, kdc}), nil
	}
	plan = append(plan, []string{"ksetup", kdcAdd, realm, kdc})
	for _, h := range hosts {
		if !hostRe.MatchString(h) {
			return nil, fmt.Errorf("host %q: a host name", h)
		}
		plan = append(plan, []string{"ksetup", add, h, realm})
	}
	return plan, nil
}

func setupCmd() *cobra.Command {
	var realm, kdc string
	var hosts []string
	var remove, print bool
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "one-time, as administrator: tell Windows where the realm's KDC is (ksetup)",
		Long: `Runs ksetup /addkdc and ksetup /addhosttorealmmap. Needs an elevated prompt.

Also needed, and not done here:
  - the machine's clock within five minutes of the KDC's (Kerberos refuses a
    skewed clock): w32tm /resync;
  - the KDC reachable by NAME on UDP/88 (and TCP/88), from this machine;
  - the share opened by its DNS NAME, never its IP address: Windows falls back
    to NTLM for an address, and the ticket is for cifs/<name>;
  - Microsoft documents a restart after /addkdc; the lab needed none.

Check the result, as the user, after authn-kinit:  klist
You should see krbtgt/REALM and, after opening the share, cifs/<host>.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := ksetupPlan(realm, kdc, hosts, remove)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if print || runtime.GOOS != "windows" {
				for _, c := range plan {
					fmt.Fprintln(out, strings.Join(c, " "))
				}
				if !print {
					fmt.Fprintln(cmd.ErrOrStderr(), "(not Windows: printed, not run)")
				}
				return nil
			}
			for _, c := range plan {
				fmt.Fprintln(out, strings.Join(c, " "))
				run := exec.CommandContext(cmd.Context(), c[0], c[1:]...)
				run.Stdout, run.Stderr = out, cmd.ErrOrStderr()
				if err := run.Run(); err != nil {
					return fmt.Errorf("%s: %w (an elevated prompt is needed)", strings.Join(c, " "), err)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&realm, "realm", "", "the Kerberos realm, e.g. EXAMPLE.ORG")
	cmd.Flags().StringVar(&kdc, "kdc", "", "the KDC's host name")
	cmd.Flags().StringSliceVar(&hosts, "host", nil, "a file server's name, as people type it (repeatable)")
	cmd.Flags().BoolVar(&remove, "remove", false, "undo the setup")
	cmd.Flags().BoolVar(&print, "print", false, "print the commands, run nothing")
	return cmd
}
