// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownerOnlyAttributes is the SECURITY_ATTRIBUTES that CreateFile takes: a
// protected DACL with one entry, the current account. CreateFile applies it as
// the file is made, so there is no moment when the file has the folder's
// access list. (CreateFile ignores it when it opens an existing file; every
// call here uses CREATE_NEW.)
func ownerOnlyAttributes() (*windows.SecurityAttributes, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sddl, err := ownerOnlySDDL(tu.User.Sid.String())
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}, nil
}

// createExclusive makes a new file that only the current account can open, and
// fails if the name exists (CREATE_NEW).
func createExclusive(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	sa, err := ownerOnlyAttributes()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// createTemp is os.CreateTemp with the same access list as createExclusive: a
// new name, retried while it is taken.
func createTemp(dir string) (*os.File, error) {
	for i := 0; ; i++ {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		f, err := createExclusive(filepath.Join(dir, ".authn-kinit-"+hex.EncodeToString(b[:])))
		if errors.Is(err, fs.ErrExist) && i < 100 {
			continue
		}
		return f, err
	}
}
