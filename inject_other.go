// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package main

import "errors"

// injectSupported is false off Windows: there is no logon-session credential
// cache to submit a ticket to. --cred-file writes the KRB-CRED (a .kirbi) for
// whatever else reads one.
const injectSupported = false

func injectCred([]byte) error {
	return errors.New("loading a ticket into a logon session is Windows only")
}
