// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"strings"
)

// ownerOnlySDDL is the security descriptor a private file is created with on
// Windows, in the Security Descriptor String Format:
//
//	D:P(A;;FA;;;<sid>)
//
// D: a DACL; P: it is PROTECTED (SE_DACL_PROTECTED), so the folder's entries are
// never inherited; one ACE, A (allow), no flags, FA (FILE_ALL_ACCESS), for the
// account's own SID. Nothing else: not SYSTEM, not Administrators. SYSTEM and
// the administrators do not need an entry to reach the file: they can take
// ownership or use the backup privilege, which no ACE can refuse, and the
// account that wrote the ticket is never locked out of it.
//
// It lives in a file with no build tag so that every platform tests the string;
// only Windows can use it.
func ownerOnlySDDL(sid string) (string, error) {
	// A SID string is "S-1-..." and nothing else; anything with a parenthesis
	// or a semicolon would add an entry to the list.
	if !strings.HasPrefix(sid, "S-1-") || strings.ContainsAny(sid, "();:\x00 ") {
		return "", errors.New("not a SID string: " + sid)
	}
	return "D:P(A;;FA;;;" + sid + ")", nil
}
