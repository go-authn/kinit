// SPDX-License-Identifier: BSD-3-Clause

package kinit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The program is installed as authn-kinit: `go install` names the binary after
// the last element of the package path, so a main package at the module root
// would be installed as `kinit`, which collides with MIT's and Heimdal's kinit
// and with the kinit.exe of MIT Kerberos for Windows and of Java runtimes.
func TestTheMainPackageLivesAtCmdAuthnKinit(t *testing.T) {
	var mains []string
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if strings.Contains(string(b), "\npackage main\n") || strings.HasPrefix(string(b), "package main\n") {
				mains = append(mains, filepath.ToSlash(filepath.Dir(p)))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range mains {
		if dir != "cmd/authn-kinit" {
			t.Errorf("a main package at %q: only cmd/authn-kinit may be one (a root or other one installs as %q)", dir, filepath.Base(dir))
		}
	}
	if len(mains) == 0 {
		t.Error("no main package found: expected cmd/authn-kinit")
	}
	if _, err := os.Stat("main.go"); err == nil {
		t.Error("main.go at the module root")
	}
}
