// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
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
//
// With --kdc-proxy the KDC is reached over HTTPS as well (MS-KKDCP), through
// Windows' own client policy "Specify KDC proxy servers for Kerberos clients"
// (Computer Configuration > Administrative Templates > System > Kerberos;
// Kerberos.admx, ADMX_Kerberos/KdcProxyServer in the Policy CSP). The ADMX
// stores it under
//
//	HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos
//	    KdcProxyServer_Enabled = 1 (DWORD)
//	    KdcProxy\ProxyServers   one value per mapping: the NAME is a DNS suffix
//	                            ("host.contoso.com" full match, ".contoso.com"
//	                            suffix, "*" default) and the DATA the proxies,
//	                            "<https proxy1.contoso.com proxy2.contoso.com />"
//
// Its documented syntax carries a host name and nothing else: Windows then
// uses its default port (443) and path (/KdcProxy), which is what
// `--kdc-proxy` accepts and nothing more, rather than a syntax invented here.

var (
	realmRe = regexp.MustCompile(`^[A-Z0-9]([A-Z0-9.-]{0,253}[A-Z0-9])?$`)
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$`)
)

const (
	kerberosLsaKey  = `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos`
	kerberosPolicy  = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos`
	kdcProxyServers = kerberosPolicy + `\KdcProxy\ProxyServers`
)

// ksetupPlan is the ksetup invocations that set a machine up (or take it down
// again), each one a program and its arguments: never a shell line, so that a
// name cannot become a command.
func ksetupPlan(realm, kdc string, hosts []string, remove bool) ([][]string, error) {
	steps, err := setupPlan(realm, kdc, hosts, "", remove)
	if err != nil {
		return nil, err
	}
	var plan [][]string
	for _, s := range steps {
		plan = append(plan, s.argv)
	}
	return plan, nil
}

// A step is one command and, when running it twice would not be harmless, the
// registry value that says whether it is already done (go-authn/kinit#5:
// `ksetup /addkdc` appends without looking, so a second run listed the KDC
// twice). Reading it first is how setup is idempotent.
type step struct {
	argv  []string
	state *regItem
}

// regItem is "does this registry value hold this item". An empty item asks
// only whether the value exists.
type regItem struct{ key, value, item string }

// setupPlan is every command of a setup, in order.
func setupPlan(realm, kdc string, hosts []string, proxy string, remove bool) ([]step, error) {
	if !realmRe.MatchString(realm) {
		return nil, fmt.Errorf("realm %q: capital letters, digits, dots and hyphens (e.g. EXAMPLE.ORG)", realm)
	}
	if !hostRe.MatchString(kdc) {
		return nil, fmt.Errorf("kdc %q: a host name", kdc)
	}
	if len(hosts) == 0 {
		return nil, errors.New("give at least one --host: the file server's name, as people type it")
	}
	for _, h := range hosts {
		if !hostRe.MatchString(h) {
			return nil, fmt.Errorf("host %q: a host name", h)
		}
	}
	proxyHost := ""
	if proxy != "" {
		var err error
		if proxyHost, err = proxyHostOf(proxy); err != nil {
			return nil, err
		}
	}
	kdcs := &regItem{kerberosLsaKey + `\Domains\` + realm, "KdcNames", kdc}
	var plan []step
	if remove {
		for _, h := range hosts {
			plan = append(plan, step{[]string{"ksetup", "/delhosttorealmmap", h, realm},
				&regItem{kerberosLsaKey + `\HostToRealm\` + realm, "SpnMappings", h}})
		}
		plan = append(plan, step{[]string{"ksetup", "/delkdc", realm, kdc}, kdcs})
		if proxyHost != "" {
			// The switch (KdcProxyServer_Enabled) stays: it is the policy's, other
			// mappings may need it, and with no mapping it does nothing.
			name := proxyValueName(realm)
			plan = append(plan, step{[]string{"reg", "delete", kdcProxyServers, "/v", name, "/f"},
				&regItem{kdcProxyServers, name, ""}})
		}
		return plan, nil
	}
	plan = append(plan, step{[]string{"ksetup", "/addkdc", realm, kdc}, kdcs})
	for _, h := range hosts {
		plan = append(plan, step{[]string{"ksetup", "/addhosttorealmmap", h, realm},
			&regItem{kerberosLsaKey + `\HostToRealm\` + realm, "SpnMappings", h}})
	}
	if proxyHost != "" {
		// reg add /f overwrites: the same value written twice is the same value.
		plan = append(plan,
			step{argv: []string{"reg", "add", kerberosPolicy, "/v", "KdcProxyServer_Enabled", "/t", "REG_DWORD", "/d", "1", "/f"}},
			step{argv: []string{"reg", "add", kdcProxyServers, "/v", proxyValueName(realm), "/t", "REG_SZ", "/d", "<https " + proxyHost + " />", "/f"}})
	}
	return plan, nil
}

// proxyValueName is the DNS suffix the mapping is keyed by: the realm, as DNS
// writes it. A realm is a DNS name in capitals; the policy's names are
// "host.contoso.com" or ".contoso.com", in lower case.
func proxyValueName(realm string) string { return strings.ToLower(realm) }

// proxyHostOf accepts https://host/KdcProxy and returns host. Anything else
// is refused: the documented policy syntax cannot say another port or path.
func proxyHostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("--kdc-proxy %q: write https://HOST/KdcProxy", raw)
	}
	if u.Port() != "" && u.Port() != "443" {
		return "", fmt.Errorf("--kdc-proxy %q: Windows' policy syntax (<https host />) cannot name a port; the proxy must answer on 443", raw)
	}
	if u.Path != "/KdcProxy" {
		return "", fmt.Errorf("--kdc-proxy %q: Windows' policy syntax (<https host />) cannot name a path; the proxy must answer at /KdcProxy", raw)
	}
	if !hostRe.MatchString(u.Hostname()) {
		return "", fmt.Errorf("--kdc-proxy %q: the host must be a name", raw)
	}
	return u.Hostname(), nil
}

// parseRegQuery returns the data of the value `reg query KEY /v VALUE` printed:
// the text after the type (REG_SZ, REG_MULTI_SZ, ...). A REG_MULTI_SZ's items
// are joined by the two characters \0 in that output.
func parseRegQuery(out, value string) (data string, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], value) && strings.HasPrefix(f[1], "REG_") {
			rest := strings.TrimSpace(line)
			rest = strings.TrimSpace(rest[len(f[0]):])
			rest = strings.TrimSpace(rest[len(f[1]):])
			return rest, true
		}
	}
	return "", false
}

// has says whether the registry already holds what s.state names.
func (r *regItem) has(run func(argv []string) (string, error)) (bool, error) {
	out, err := run([]string{"reg", "query", r.key, "/v", r.value})
	data, ok := parseRegQuery(out, r.value)
	if !ok {
		// reg exits 1 for a missing key or value, with a message that says so;
		// anything else is not "absent", it is "could not look".
		if err != nil && !strings.Contains(out, "unable to find") {
			return false, fmt.Errorf("reg query %s: %w: %s", r.key, err, strings.TrimSpace(out))
		}
		return false, nil
	}
	if r.item == "" {
		return true, nil
	}
	for _, it := range strings.Split(data, `\0`) {
		if strings.EqualFold(strings.TrimSpace(it), r.item) {
			return true, nil
		}
	}
	return false, nil
}

// applySetup runs the plan. Before a step that adds, it asks whether the item
// is there; before one that removes, whether it is not. A step already done is
// said so and skipped, which is what makes setup safe to run again.
func applySetup(plan []step, remove bool, run func(argv []string) (string, error), out io.Writer) error {
	for _, s := range plan {
		line := strings.Join(s.argv, " ")
		if s.state != nil {
			there, err := s.state.has(run)
			if err != nil {
				return err
			}
			if there == !remove {
				fmt.Fprintf(out, "already done, skipped: %s\n", line)
				continue
			}
		}
		fmt.Fprintln(out, line)
		if o, err := run(s.argv); err != nil {
			return fmt.Errorf("%s: %w (an elevated prompt is needed): %s", line, err, strings.TrimSpace(o))
		}
	}
	return nil
}

func execRun(ctx context.Context) func(argv []string) (string, error) {
	return func(argv []string) (string, error) {
		var b bytes.Buffer
		c := exec.CommandContext(ctx, argv[0], argv[1:]...)
		c.Stdout, c.Stderr = &b, &b
		err := c.Run()
		return b.String(), err
	}
}

func setupCmd() *cobra.Command {
	var realm, kdc, proxy string
	var hosts []string
	var remove, print bool
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "one-time, as administrator: tell Windows where the realm's KDC is (ksetup), and its HTTPS proxy",
		Long: `Runs ksetup /addkdc and ksetup /addhosttorealmmap. Needs an elevated prompt.
Safe to run again: what is already there is read from the registry first and
not added twice.

With --kdc-proxy https://HOST/KdcProxy it also writes Windows' "Specify KDC
proxy servers for Kerberos clients" policy (MS-KKDCP, Kerberos over HTTPS):
KdcProxyServer_Enabled = 1 and, under KdcProxy\ProxyServers, a value named
after the realm (lower case) holding "<https HOST />". Windows then reaches
the KDC through port 443 when it cannot reach it directly. The proxy must
answer on port 443 at /KdcProxy, and its certificate must be trusted by the
machine.

Also needed, and not done here:
  - the machine's clock within five minutes of the KDC's (Kerberos refuses a
    skewed clock): w32tm /resync;
  - the KDC reachable by NAME on UDP/88 (and TCP/88), from this machine, unless
    --kdc-proxy is used and port 88 is closed;
  - the share opened by its DNS NAME, never its IP address: Windows falls back
    to NTLM for an address, and the ticket is for cifs/<name>;
  - Microsoft documents a restart after /addkdc; the lab needed none.

Check the result, as the user, after authn-kinit:  klist
You should see krbtgt/REALM and, after opening the share, cifs/<host>.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := setupPlan(realm, kdc, hosts, proxy, remove)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if print || runtime.GOOS != "windows" {
				for _, s := range plan {
					fmt.Fprintln(out, strings.Join(s.argv, " "))
				}
				if !print {
					fmt.Fprintln(cmd.ErrOrStderr(), "(not Windows: printed, not run)")
				}
				return nil
			}
			return applySetup(plan, remove, execRun(cmd.Context()), out)
		},
	}
	cmd.Flags().StringVar(&realm, "realm", "", "the Kerberos realm, e.g. EXAMPLE.ORG")
	cmd.Flags().StringVar(&kdc, "kdc", "", "the KDC's host name")
	cmd.Flags().StringVar(&proxy, "kdc-proxy", "", "the KDC proxy (MS-KKDCP), https://HOST/KdcProxy: Kerberos over port 443")
	cmd.Flags().StringSliceVar(&hosts, "host", nil, "a file server's name, as people type it (repeatable)")
	cmd.Flags().BoolVar(&remove, "remove", false, "undo the setup")
	cmd.Flags().BoolVar(&print, "print", false, "print the commands, run nothing")
	return cmd
}
