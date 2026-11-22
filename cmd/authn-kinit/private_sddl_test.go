// SPDX-License-Identifier: BSD-3-Clause

package main

import "testing"

func TestOwnerOnlySDDL(t *testing.T) {
	const sid = "S-1-5-21-1004336348-1177238915-682003330-1000"
	got, err := ownerOnlySDDL(sid)
	if err != nil {
		t.Fatal(err)
	}
	// Protected, one allow entry, FILE_ALL_ACCESS, that SID, nothing else.
	if want := "D:P(A;;FA;;;" + sid + ")"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// A value that is not a SID must not reach the descriptor: a ")" or ";" in it
// would write a second entry, a missing prefix would name something else.
func TestOwnerOnlySDDLRefusesWhatIsNotASID(t *testing.T) {
	for _, s := range []string{
		"", "WD", "S-2-5-1", "x S-1-5-18",
		"S-1-5-18)(A;;FA;;;WD", "S-1-5-18;", "S-1-5-18(", "S-1-5:18", "S-1-5 18", "S-1-5-18\x00",
	} {
		if got, err := ownerOnlySDDL(s); err == nil {
			t.Errorf("%q accepted: %q", s, got)
		}
	}
}
