// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package main

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// injectSupported says this system can load a ticket into a logon session.
const injectSupported = true

var (
	secur32 = syscall.NewLazyDLL("secur32.dll")
	advapi  = syscall.NewLazyDLL("advapi32.dll")

	pConnect = secur32.NewProc("LsaConnectUntrusted")
	pLookup  = secur32.NewProc("LsaLookupAuthenticationPackage")
	pCall    = secur32.NewProc("LsaCallAuthenticationPackage")
	pFree    = secur32.NewProc("LsaFreeReturnBuffer")
	pDereg   = secur32.NewProc("LsaDeregisterLogonProcess")
	pWinErr  = advapi.NewProc("LsaNtStatusToWinError")
)

// KerbSubmitTicketMessage is value 21 of KERB_PROTOCOL_MESSAGE_TYPE
// (ntsecapi.h), counted from the enumeration; the lab spike proved it on
// Windows 11 build 26200.
const kerbSubmitTicketMessage = 21

type lsaString struct {
	Length, MaximumLength uint16
	Buffer                *byte
}

// kerbSubmitTktRequest is KERB_SUBMIT_TKT_REQUEST (ntsecapi.h): message type,
// LUID, flags, KERB_CRYPTO_KEY32 {KeyType, Length, Offset}, KerbCredSize,
// KerbCredOffset; the KRB-CRED bytes follow the structure. Microsoft's page for
// the structure answers 404; this layout is validated by the result, not by
// documentation.
type kerbSubmitTktRequest struct {
	MessageType    uint32
	LogonIDLow     uint32
	LogonIDHigh    int32
	Flags          uint32
	KeyType        int32
	KeyLength      uint32
	KeyOffset      uint32
	KerbCredSize   uint32
	KerbCredOffset uint32
}

func ntstatus(what string, st uintptr) error {
	if st == 0 {
		return nil
	}
	w, _, _ := pWinErr.Call(st)
	return fmt.Errorf("%s: NTSTATUS 0x%08x (win32 %d)", what, uint32(st), w)
}

// injectCred submits a KRB-CRED to the Kerberos package for the CURRENT logon
// session (LogonId zero), with no privilege: KerbSubmitTicketMessage into
// one's own session needs none (SeTcbPrivilege is for another's).
//
// It must run in the user's interactive logon session: from a plain SSH
// session (no Kerberos logon session) or a service it fails with
// 0xc000005f, and a SYSTEM task would fill SYSTEM's cache, not the user's.
func injectCred(cred []byte) error {
	if len(cred) == 0 {
		return errors.New("no ticket")
	}
	var h syscall.Handle
	st, _, _ := pConnect.Call(uintptr(unsafe.Pointer(&h)))
	if err := ntstatus("LsaConnectUntrusted", st); err != nil {
		return err
	}
	defer pDereg.Call(uintptr(h))

	name := []byte("Kerberos")
	ls := lsaString{Length: uint16(len(name)), MaximumLength: uint16(len(name)), Buffer: &name[0]}
	var pkg uint32
	st, _, _ = pLookup.Call(uintptr(h), uintptr(unsafe.Pointer(&ls)), uintptr(unsafe.Pointer(&pkg)))
	if err := ntstatus("LsaLookupAuthenticationPackage", st); err != nil {
		return err
	}

	hdr := unsafe.Sizeof(kerbSubmitTktRequest{})
	buf := make([]byte, int(hdr)+len(cred))
	r := (*kerbSubmitTktRequest)(unsafe.Pointer(&buf[0]))
	r.MessageType = kerbSubmitTicketMessage
	r.KerbCredSize = uint32(len(cred))
	r.KerbCredOffset = uint32(hdr)
	copy(buf[hdr:], cred)

	var ret uintptr
	var retLen, proto uint32
	st, _, _ = pCall.Call(uintptr(h), uintptr(pkg), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&ret)), uintptr(unsafe.Pointer(&retLen)), uintptr(unsafe.Pointer(&proto)))
	if ret != 0 {
		pFree.Call(ret)
	}
	// The key is in this buffer: do not leave it behind.
	clear(buf)
	if err := ntstatus("LsaCallAuthenticationPackage", st); err != nil {
		return err
	}
	return ntstatus("KerbSubmitTicketMessage (protocol status)", uintptr(proto))
}
