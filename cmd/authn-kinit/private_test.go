package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Suspicion 3 (POSIX half). The ticket went through os.WriteFile into whatever
// was at the path: a symlink sent it to the link's target (here a 0644 file
// somebody else reads), and an existing 0644 file held it until a later chmod.
func TestACredFileIsNeverWrittenThroughAnExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks and modes are not what Windows checks")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "world-readable")
	if err := os.WriteFile(victim, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cred.kirbi")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(path, []byte("TICKET")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "old" {
		t.Fatalf("the ticket was written through the link into %q", b)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cred file is %v, want a regular 0600 file", fi.Mode())
	}
	if b, _ := os.ReadFile(path); string(b) != "TICKET" {
		t.Fatalf("cred file holds %q", b)
	}
}

// A temporary file that cannot be made is an error from writePrivate, and
// nothing is created. The recover turns a crash on a missing file into a
// failed assertion, so the test says what the guard is for.
func TestAFailedCreateTempIsAnErrorAndLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("writePrivate crashed instead of returning the error: %v", r)
		}
	}()
	err := writePrivate(filepath.Join(dir, "no", "such", "cred"), []byte("x"))
	if err == nil {
		t.Fatal("no error when the temporary file cannot be made")
	}
	ents, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(ents) != 0 {
		t.Fatalf("%d entries left in %s, want none", len(ents), dir)
	}
}

func TestACredFileLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	// A name that cannot be replaced (a directory with something in it): the
	// error comes back and the temporary file is removed.
	busy := filepath.Join(dir, "busy")
	if err := os.MkdirAll(filepath.Join(busy, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(busy, []byte("x")); err == nil {
		t.Fatal("replaced a directory")
	}
	if err := os.RemoveAll(busy); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(filepath.Join(dir, "cred"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("%d entries, want only the cred file", len(ents))
	}
}

// A directory others can write to is refused: the ticket could be swapped
// there (go-authn/harden's privfile).
func TestACredFileIsRefusedInAWritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes are Unix")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cred")
	if err := writePrivate(path, []byte("TICKET")); err == nil {
		t.Fatal("a ticket was written into a world-writable directory")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the file exists")
	}
}
