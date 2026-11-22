# Changelog

## v0.3.4

- Fixed (#14): `setup --kdc-proxy` no longer runs `ksetup /addkdc`. A
  `KdcNames` value for the realm makes Windows try only that address on port 88
  and never the MS-KKDCP proxy (`net use` 1223, event 302); deleting it made the
  proof pass on a fresh Windows 11. A `KdcNames` left by v0.3.0 is deleted, so
  running `setup --kdc-proxy` again repairs the machine.
- `--kdc` is optional with `--kdc-proxy` (and unused); without a proxy it is
  still required. A missing `--realm` now says "give --realm" instead of
  `realm ""`; the realm is not derived (a realm is not always its KDC's domain).

## v0.3.3

- `--cred-file` is written by `github.com/go-authn/harden/privfile` v0.2.0
  (the temporary-file, sync and rename code, and its Windows owner-only DACL,
  moved there from this module; `keygen --out` keeps its own exclusive create).
  Behaviour change: a directory that is a symlink, belongs to another user or
  is writable by group or others (for instance `/tmp` itself) is now refused
  for `--cred-file`, as the ticket could be swapped there.

## v0.3.2

- Fixed (#10): on Windows `--cred-file` and the `keygen --out` private key are
  created with a protected DACL that holds one ACE, an allow for the current
  account's SID (FILE_ALL_ACCESS), so they no longer take the folder's access
  list. The descriptor is passed in the SECURITY_ATTRIBUTES of `CreateFile`
  (`CREATE_NEW`), so the file is never readable by anyone else, not even for a
  moment; the temporary file written before the rename is made the same way.
  SYSTEM and Administrators get no entry: they can take ownership or use the
  backup privilege whatever the DACL says, and nothing needs them to read it.
  POSIX is unchanged (0600, `O_EXCL`, `os.CreateTemp`).
- Added: `golang.org/x/sys` as a dependency (windows only).
- Tested on `windows-latest`: the DACL is read back with
  `GetNamedSecurityInfo`; exactly one non-inherited allow ACE for the owner's
  SID, and `SE_DACL_PROTECTED` set.

## v0.3.1

Security audit 2026-11-21 (suspicions, go-authn/kinit).

- Fixed: `--cred-file` is written to a new file (`os.CreateTemp`, 0600) and
  renamed over the path. It used `os.WriteFile`, which writes into an existing
  file and keeps its mode (a 0644 file held the ticket until the chmod after),
  and follows a symlink (the ticket landed in the link's target).
- Documented: on Windows the 0600 mode is only the read-only attribute, so
  `--cred-file` takes the permissions of its folder; `keygen --out` too. Use a
  folder only the account can open. Not fixed in code: a DACL needs
  `golang.org/x/sys/windows`, which this module does not carry, and it cannot
  be tested on the machines this was audited from.
- Checked and left unchanged: `keygen` already creates its file with
  `O_EXCL` and 0600 on POSIX, so there is no looser-mode file to write into.

## v0.3.0

- Added: `setup --kdc-proxy https://HOST/KdcProxy` writes Windows' KdcProxy
  client policy (MS-KKDCP; `Kerberos.admx`: `KdcProxyServer_Enabled` and
  `KdcProxy\ProxyServers`), so the KDC is reached through port 443.
- Fixed: `setup` is idempotent (#5). It reads `KdcNames` and `SpnMappings`
  first and adds only what is missing; `--remove` skips what is already gone.

## Unreleased (v0.2.0)

- **Breaking: the install path changed.** The program moved from the module
  root to `cmd/authn-kinit`. v0.1.0's `go install github.com/go-authn/kinit@v0.1.0`
  built `kinit` / `kinit.exe`, colliding with MIT and Heimdal `kinit` and with
  the `kinit.exe` of MIT Kerberos for Windows and of Java runtimes. Use
  `go install github.com/go-authn/kinit/cmd/authn-kinit@latest`; the binary is
  `authn-kinit`. A test and a CI step keep it so.
- golang.org/x/net v0.7.0 -> v0.63.0 and golang.org/x/crypto v0.6.0 -> v0.59.0.

## v0.1.0

- First version: interactive login (loopback flow), unattended machine key
  (private_key_jwt), `keygen`, `setup` (ksetup), ticket loaded with
  `KerbSubmitTicketMessage`.
