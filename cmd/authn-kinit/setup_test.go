// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// fakeWindows is the registry as ksetup and reg.exe leave it, in the shape
// `reg query` prints it (taken from a Windows 11 machine): ksetup /addkdc
// APPENDS without looking, which is why setup must look first (kinit#5).
type fakeWindows struct {
	values map[string]map[string]string // key -> value name -> "REG_x data"
	log    []string
}

func newFakeWindows() *fakeWindows { return &fakeWindows{values: map[string]map[string]string{}} }

func (w *fakeWindows) set(key, name, typ, data string) {
	if w.values[key] == nil {
		w.values[key] = map[string]string{}
	}
	w.values[key][name] = typ + "    " + data
}

func (w *fakeWindows) appendMulti(key, name, item string) {
	if cur, ok := w.values[key][name]; ok {
		_, data, _ := strings.Cut(cur, "    ")
		item = data + `\0` + item
	}
	w.set(key, name, "REG_MULTI_SZ", item)
}

func (w *fakeWindows) run(argv []string) (string, error) {
	w.log = append(w.log, strings.Join(argv, " "))
	switch {
	case argv[0] == "reg" && argv[1] == "query":
		v, ok := w.values[argv[2]][argv[4]]
		if !ok {
			return "ERROR: The system was unable to find the specified registry key or value.\r\n", errors.New("exit status 1")
		}
		return "\r\n" + argv[2] + "\r\n    " + argv[4] + "    " + v + "\r\n\r\n", nil
	case argv[0] == "reg" && argv[1] == "add":
		w.set(argv[2], argv[4], argv[6], argv[8])
		return "The operation completed successfully.\r\n", nil
	case argv[0] == "reg" && argv[1] == "delete":
		delete(w.values[argv[2]], argv[4])
		return "The operation completed successfully.\r\n", nil
	case argv[0] == "ksetup" && argv[1] == "/addkdc":
		w.appendMulti(kerberosLsaKey+`\Domains\`+argv[2], "KdcNames", argv[3])
	case argv[0] == "ksetup" && argv[1] == "/addhosttorealmmap":
		w.appendMulti(kerberosLsaKey+`\HostToRealm\`+argv[3], "SpnMappings", argv[2])
	case argv[0] == "ksetup" && argv[1] == "/delkdc":
		delete(w.values[kerberosLsaKey+`\Domains\`+argv[2]], "KdcNames")
	case argv[0] == "ksetup" && argv[1] == "/delhosttorealmmap":
		delete(w.values[kerberosLsaKey+`\HostToRealm\`+argv[3]], "SpnMappings")
	default:
		return "", errors.New("unexpected " + strings.Join(argv, " "))
	}
	return "Done\r\n", nil
}

func (w *fakeWindows) count(prefix string) int {
	n := 0
	for _, l := range w.log {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

func TestSetupPlanWithAProxy(t *testing.T) {
	plan, err := setupPlan("EXAMPLE.ORG", "kdc.example.org", []string{"fs.example.org"}, "https://kdc.example.org/KdcProxy", false)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range plan {
		got = append(got, strings.Join(s.argv, " "))
	}
	want := []string{
		"ksetup /addkdc EXAMPLE.ORG kdc.example.org",
		"ksetup /addhosttorealmmap fs.example.org EXAMPLE.ORG",
		`reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos /v KdcProxyServer_Enabled /t REG_DWORD /d 1 /f`,
		`reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\KdcProxy\ProxyServers /v example.org /t REG_SZ /d <https kdc.example.org /> /f`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Without --kdc-proxy nothing about a proxy is written.
	plain, _ := setupPlan("EXAMPLE.ORG", "kdc.example.org", []string{"fs.example.org"}, "", false)
	for _, s := range plain {
		if s.argv[0] == "reg" && s.argv[1] == "add" {
			t.Errorf("a registry write without --kdc-proxy: %v", s.argv)
		}
	}
}

func TestSetupRefusesAProxyItCannotExpress(t *testing.T) {
	for _, bad := range []string{
		"http://kdc.example.org/KdcProxy",          // Windows requires HTTPS
		"https://kdc.example.org:8443/KdcProxy",    // the policy's syntax cannot say a port
		"https://kdc.example.org/other",            // nor a path
		"https://kdc.example.org",                  // the path is /KdcProxy
		"https://user:pw@kdc.example.org/KdcProxy", // no credentials in a URL
		"https://kdc.example.org/KdcProxy?x=1",
		"https:///KdcProxy",
		"https://kdc example.org/KdcProxy",
		"https://kdc.example.org\" /> <https evil/KdcProxy",
		"kdc.example.org",
		"https://-kdc.example.org/KdcProxy", // a URL that parses, but not a host name
		"https://kdc_1.example.org/KdcProxy",
	} {
		if _, err := setupPlan("EXAMPLE.ORG", "kdc.example.org", []string{"fs.example.org"}, bad, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// The control: the accepted form, with the explicit default port.
	for _, ok := range []string{"https://kdc.example.org/KdcProxy", "https://kdc.example.org:443/KdcProxy"} {
		if _, err := setupPlan("EXAMPLE.ORG", "kdc.example.org", []string{"fs.example.org"}, ok, false); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}

func TestParseRegQuery(t *testing.T) {
	out := "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Domains\\MESOCENTRE.TEST\r\n    KdcNames    REG_MULTI_SZ    kdc.mesocentre.test\\0kdc2.mesocentre.test\r\n\r\n"
	data, ok := parseRegQuery(out, "KdcNames")
	if !ok || data != `kdc.mesocentre.test\0kdc2.mesocentre.test` {
		t.Errorf("%q %v", data, ok)
	}
	if _, ok := parseRegQuery(out, "SpnMappings"); ok {
		t.Error("a value that is not there was found")
	}
	if _, ok := parseRegQuery("ERROR: The system was unable to find the specified registry key or value.", "KdcNames"); ok {
		t.Error("an error message was read as data")
	}
}

// Run twice, setup leaves what one run leaves (kinit#5), and the second says
// so; removed twice, the second finds nothing to do. Without the look-first the
// fake, like ksetup, lists the KDC twice, which the control below shows.
func TestSetupIsIdempotent(t *testing.T) {
	args := func(remove bool) []step {
		p, err := setupPlan("MESOCENTRE.TEST", "kdc.mesocentre.test", []string{"fs.mesocentre.test"}, "https://kdc.mesocentre.test/KdcProxy", remove)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	kdcKey := kerberosLsaKey + `\Domains\MESOCENTRE.TEST`
	hostKey := kerberosLsaKey + `\HostToRealm\MESOCENTRE.TEST`

	// The control: the commands run blindly, as v0.2.0 ran them.
	blind := newFakeWindows()
	for range 2 {
		for _, s := range args(false) {
			blind.run(s.argv)
		}
	}
	if got := blind.values[kdcKey]["KdcNames"]; !strings.Contains(got, `\0`) {
		t.Fatalf("the control: blind runs should list the KDC twice, got %q", got)
	}

	w := newFakeWindows()
	var out bytes.Buffer
	for i := range 3 {
		out.Reset()
		if err := applySetup(args(false), false, w.run, &out); err != nil {
			t.Fatal(err)
		}
		if i > 0 && strings.Count(out.String(), "already done, skipped") != 2 {
			t.Errorf("run %d should skip the two ksetup steps:\n%s", i+1, out.String())
		}
	}
	if got := w.values[kdcKey]["KdcNames"]; got != "REG_MULTI_SZ    kdc.mesocentre.test" {
		t.Errorf("KdcNames after three runs: %q", got)
	}
	if got := w.values[hostKey]["SpnMappings"]; got != "REG_MULTI_SZ    fs.mesocentre.test" {
		t.Errorf("SpnMappings after three runs: %q", got)
	}
	if n := w.count("ksetup /addkdc"); n != 1 {
		t.Errorf("ksetup /addkdc ran %d times", n)
	}
	if got := w.values[kdcProxyServers]["mesocentre.test"]; got != "REG_SZ    <https kdc.mesocentre.test />" {
		t.Errorf("the proxy mapping: %q", got)
	}
	if got := w.values[kerberosPolicy]["KdcProxyServer_Enabled"]; got != "REG_DWORD    1" {
		t.Errorf("the switch: %q", got)
	}

	for range 2 {
		if err := applySetup(args(true), true, w.run, &out); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := w.values[kdcKey]["KdcNames"]; ok {
		t.Error("the KDC is still listed after --remove")
	}
	if _, ok := w.values[kdcProxyServers]["mesocentre.test"]; ok {
		t.Error("the proxy mapping is still there after --remove")
	}
	if n := w.count("ksetup /delkdc"); n != 1 {
		t.Errorf("ksetup /delkdc ran %d times", n)
	}
}

func TestSetupStopsWhenTheRegistryCannotBeRead(t *testing.T) {
	plan, _ := setupPlan("EXAMPLE.ORG", "kdc.example.org", []string{"fs.example.org"}, "", false)
	var ran []string
	err := applySetup(plan, false, func(argv []string) (string, error) {
		ran = append(ran, argv[0]+" "+argv[1])
		if argv[0] == "reg" {
			return "ERROR: Access is denied.", errors.New("exit status 1")
		}
		return "", nil
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("an unreadable registry was read as an empty one")
	}
	for _, r := range ran {
		if strings.HasPrefix(r, "ksetup") {
			t.Errorf("ksetup ran after the read failed: %v", ran)
		}
	}
}
