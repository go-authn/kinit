# Changelog

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
