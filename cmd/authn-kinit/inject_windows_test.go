// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"strings"
	"testing"
)

// The one thing a CI runner can check without a realm: the call reaches the
// Local Security Authority and a malformed ticket is REFUSED by it, with a
// status, not accepted and not a crash. A layout of the request that was wrong
// would fail earlier, or differently. (The proof that a REAL ticket is taken
// is the lab run, recorded in the README.)
func TestInjectRefusesMalformedTicket(t *testing.T) {
	err := injectCred([]byte("this is not a KRB-CRED"))
	if err == nil {
		t.Fatal("garbage was accepted as a ticket")
	}
	if !strings.Contains(err.Error(), "NTSTATUS") {
		t.Errorf("not an LSA status: %v", err)
	}
	if err := injectCred(nil); err == nil {
		t.Error("an empty ticket was accepted")
	}
}
