# Changelog

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
