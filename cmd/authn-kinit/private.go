package main

import "github.com/go-authn/harden/privfile"

// writePrivate puts data at path as a file only its owner can read: a 0600
// temporary file (on Windows, a protected owner-only DACL, set as the file is
// made), synced and renamed over path. The ticket is never in a file that
// already existed, and a symlink at path is replaced, not followed. The
// directory must belong to the caller and not be writable by group or others.
// The work is go-authn/harden's privfile.Write.
func writePrivate(path string, data []byte) error { return privfile.Write(path, data) }
