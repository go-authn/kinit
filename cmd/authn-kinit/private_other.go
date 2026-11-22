// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package main

import "os"

// createExclusive makes a new file, mode 0600, and fails if the name exists.
func createExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// createTemp makes a new file, mode 0600, under a name nobody chose.
func createTemp(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".authn-kinit-*")
}
