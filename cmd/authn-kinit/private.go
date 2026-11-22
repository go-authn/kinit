package main

import (
	"errors"
	"os"
	"path/filepath"
)

// writePrivate puts data at path as a file only its owner can read.
//
// The file is made first, under another name, by os.CreateTemp (O_EXCL, mode
// 0600), written, and then renamed over path. The ticket is never in a file
// that already existed: os.WriteFile on an existing file keeps ITS mode, so a
// 0644 file held the ticket until a chmod that came after, and a symlink at
// path put the ticket in whatever it pointed to. A rename replaces the name,
// not the target of a link.
//
// On Windows the mode bits mean only the read-only attribute: the file takes
// the permissions of the folder it is made in. Keep --cred-file in a folder
// only the account can open.
func writePrivate(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".authn-kinit-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	err = errors.Join(werr, f.Close())
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
