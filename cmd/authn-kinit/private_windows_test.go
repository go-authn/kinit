// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// assertOwnerOnly reads the DACL of path back and requires: it is protected
// (inherits nothing), and it holds exactly one ACE, a non-inherited allow ACE
// for the current account's SID with full access.
func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s: the DACL is not protected (control %#x): it inherits from the folder", path, ctrl)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("%s: no DACL (%v): that is full access for everyone", path, err)
	}
	if acl.AceCount != 1 {
		t.Fatalf("%s: %d ACEs, want exactly 1", path, acl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Errorf("%s: ACE type %d, want allow", path, ace.Header.AceType)
	}
	if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
		t.Errorf("%s: the ACE is inherited (flags %#x)", path, ace.Header.AceFlags)
	}
	if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); !sid.Equals(tu.User.Sid) {
		t.Errorf("%s: ACE is for %s, want the current user %s", path, sid, tu.User.Sid)
	}
	const fileAllAccess = 0x1f01ff
	if uint32(ace.Mask)&fileAllAccess != fileAllAccess {
		t.Errorf("%s: mask %#x, want FILE_ALL_ACCESS", path, ace.Mask)
	}
}

func TestACredFileHasAnOwnerOnlyDACL(t *testing.T) {
	// The folder is the harm: whatever it grants, the file must not get it.
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.kirbi")
	if err := writePrivate(path, []byte("TICKET")); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, path)
	if b, _ := os.ReadFile(path); string(b) != "TICKET" {
		t.Fatalf("cred file holds %q", b)
	}
	// A second write replaces it, and the new file is as private.
	if err := writePrivate(path, []byte("TICKET2")); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, path)
}

func TestKeygenOutputHasAnOwnerOnlyDACL(t *testing.T) {
	out := filepath.Join(t.TempDir(), "machine.pem")
	cmd := keygenCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--out", out, "--kid", "k1"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, out)
}

// The access list is there when the file is made, not after: the file as
// createExclusive returns it, still open and still empty, already has it.
func TestCreateExclusiveSetsTheDACLAtCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	f, err := createExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	assertOwnerOnly(t, path)
	if _, err := createExclusive(path); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a second create of the same name: %v, want it to exist", err)
	}
}

func TestCreateTempHasTheDACL(t *testing.T) {
	dir := t.TempDir()
	f, err := createTemp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	assertOwnerOnly(t, f.Name())
	if filepath.Dir(f.Name()) != dir {
		t.Fatalf("temp file %s is not in %s", f.Name(), dir)
	}
	if _, err := createTemp(filepath.Join(dir, "no", "such")); err == nil {
		t.Fatal("made a temp file in a folder that is not there")
	}
}
