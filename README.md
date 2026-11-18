# authn-kinit

A Kerberos ticket without a password, for SMB from a Windows machine that is
not in a domain.

A person logs in with a passkey at [go-authn/bridge](https://github.com/go-authn/bridge);
bridge asks the realm's KDC ([go-authn/kdc](https://github.com/go-authn/kdc))
for a TGT for that person; `authn-kinit` loads it into the Windows logon
session; Windows then fetches `cifs/<server>` from the KDC by itself and talks
Kerberos to the file server. No password is typed, stored or accepted anywhere
on this path, and there is no option to add one.

```
authn-kinit --issuer https://login.example.org --client kinit
```

Pure Go, `CGO_ENABLED=0`, windows/amd64 and windows/arm64. On other systems it
runs, fetches, and writes the KRB-CRED with `--cred-file`; loading a ticket into
a logon session is Windows only.

## Interactive

`authn-kinit --issuer ISSUER --client CLIENT` opens the provider's login page in
the default browser (RFC 8252 loopback flow, [go-authn/rp](https://github.com/go-authn/rp):
`127.0.0.1`, PKCE, never a web view), the person uses their passkey, and the
program receives an access token with the `kerberos` scope. It posts that to
`ISSUER/kerberos/tgt`, checks the KRB-CRED it gets back (one ticket, a session
key, not expired, etype 0), and submits it with
`LsaCallAuthenticationPackage(KerbSubmitTicketMessage)` to the current logon
session. That call needs no privilege. It must run in the person's interactive
session: from plain SSH, or as a service or SYSTEM task, it fails or fills the
wrong cache.

The client is a public bridge client registered with
`redirect_uris = ["http://127.0.0.1/callback"]`, `kerberos_tickets = true`.

## Unattended: a machine key, no secret

```
authn-kinit keygen --out C:\ProgramData\authn\machine.key --kid winpc-17-1
authn-kinit --issuer ISSUER --client winpc-17 --machine-key C:\ProgramData\authn\machine.key --kid winpc-17-1
```

`keygen` writes a P-256 private key (PKCS#8 PEM, created exclusively, never
overwritten) and prints the public JWK Set to register in the provider
(bridge's `private_key_jwt` clients, go-authn/bridge#103). The program then uses
the `client_credentials` grant with a signed assertion (RFC 7523 2.2): no shared
secret exists. Keep the key where only the account that runs the tool can read
it (an ACL on its directory; Windows ignores the file mode), and run it as that
account in its logon session, for instance a scheduled task "at log on" and
hourly "only when the user is logged on". Two things are not here yet: the
provider side of a machine's TGT (the scoped principal of a machine) waits for
go-authn/bridge#103, and the key is not yet sealed with DPAPI or a TPM.

## One-time administrator setup

```
authn-kinit setup --realm EXAMPLE.ORG --kdc kdc.example.org --host fs.example.org
```

runs `ksetup /addkdc EXAMPLE.ORG kdc.example.org` and
`ksetup /addhosttorealmmap fs.example.org EXAMPLE.ORG` (an elevated prompt;
`--print` only prints them, `--remove` undoes them). Names are validated before
anything is run, and ksetup is started without a shell. Also needed:

- the clock within five minutes of the KDC's (`w32tm /resync`);
- the KDC reachable **by name** on UDP/88 (Windows sends its TGS-REQ over UDP to
  the name `ksetup` was given; a KDC on another port needs a relay) and TCP/88;
- the share opened by **DNS name**, never by IP address: Windows falls back to
  NTLM for an address, and the ticket is for `cifs/<name>`. To refuse NTLM
  outright: `Set-SmbClientConfiguration -BlockNTLM $true`;
- Microsoft documents a restart after `/addkdc`; the lab needed none.

## Check it

```
klist
```

shows `krbtgt/EXAMPLE.ORG @ EXAMPLE.ORG` for the person after `authn-kinit`,
with ticket flags `initial pre_authent`; after opening `\\fs.example.org\share`,
also `cifs/fs.example.org`. `klist get cifs/fs.example.org` asks for it
directly. After a failed attempt `klist purge` before trying again (a second
`klist get` otherwise answers `0x520`).

## What it will not do

- Renew: a ticket lasts at most ten hours and never beyond the person's session
  at the provider. Another login is the renewal.
- Ask for a password, or keep a refresh token: it logs in, gets one ticket, and
  forgets the token.
- Follow a redirect with the token, accept `http` for a remote provider, or
  accept a credential whose session key is encrypted (it expects the clear
  etype 0 KRB-CRED the provider sends over TLS).

## Status

The pure parts are unit-tested on Linux, macOS and Windows; the Windows lane
also checks that the Local Security Authority refuses a malformed ticket with a
status. The proof with a real KDC and a real Windows 11 machine is recorded in
the pull request that added this program.
