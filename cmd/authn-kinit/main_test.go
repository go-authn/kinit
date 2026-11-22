// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func writeKey(t *testing.T, dir string, k any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// verifyJWS checks a compact JWS with the public key and returns its claims.
func verifyJWS(t *testing.T, jws string, pub any) (hdr, claims map[string]any) {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", jws)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signed := []byte(parts[0] + "." + parts[1])
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		d := sha256.Sum256(signed)
		if len(sig) != 64 || !ecdsa.Verify(k, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatal("ES256 signature does not verify")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, signed, sig) {
			t.Fatal("EdDSA signature does not verify")
		}
	}
	for i, dst := range []*map[string]any{&hdr, &claims} {
		b, _ := base64.RawURLEncoding.DecodeString(parts[i])
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatal(err)
		}
	}
	return hdr, claims
}

func TestClientAssertion(t *testing.T) {
	now := time.Now()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	seen := map[string]bool{}
	for _, c := range []struct {
		name string
		key  interface {
			Public() any
		}
		alg string
		pub any
	}{{"ES256", nil, "ES256", &ec.PublicKey}, {"EdDSA", nil, "EdDSA", edPub}} {
		var jws string
		var err error
		if c.alg == "ES256" {
			jws, err = clientAssertion(ec, "ES256", "k1", "winpc-17", "https://login.example.org/token", now)
		} else {
			jws, err = clientAssertion(edPriv, "EdDSA", "k1", "winpc-17", "https://login.example.org/token", now)
		}
		if err != nil {
			t.Fatal(err)
		}
		hdr, cl := verifyJWS(t, jws, c.pub)
		if hdr["alg"] != c.alg || hdr["kid"] != "k1" {
			t.Errorf("%s: header %v", c.name, hdr)
		}
		if cl["iss"] != "winpc-17" || cl["sub"] != "winpc-17" || cl["aud"] != "https://login.example.org/token" {
			t.Errorf("%s: claims %v", c.name, cl)
		}
		// RFC 7523 3 and bridge: a short life, and a jti that is not reused.
		exp, _ := cl["exp"].(float64)
		if d := time.Unix(int64(exp), 0).Sub(now); d <= 0 || d > 5*time.Minute {
			t.Errorf("%s: exp in %v", c.name, d)
		}
		jti, _ := cl["jti"].(string)
		if jti == "" || seen[jti] {
			t.Errorf("%s: jti %q empty or reused", c.name, jti)
		}
		seen[jti] = true
	}
}

func TestLoadMachineKey(t *testing.T) {
	dir := t.TempDir()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, alg, err := loadMachineKey(writeKey(t, dir, ec)); err != nil || alg != "ES256" {
		t.Errorf("P-256: %v %s", err, alg)
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	if _, alg, err := loadMachineKey(writeKey(t, dir, ed)); err != nil || alg != "EdDSA" {
		t.Errorf("Ed25519: %v %s", err, alg)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, k := range map[string]any{"P-384": p384, "RSA": rsaKey} {
		if _, _, err := loadMachineKey(writeKey(t, dir, k)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	junk := filepath.Join(dir, "junk")
	os.WriteFile(junk, []byte("not a key"), 0o600)
	if _, _, err := loadMachineKey(junk); err == nil {
		t.Error("junk accepted")
	}
	if _, _, err := loadMachineKey(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file accepted")
	}
}

// fakeProvider is a bridge as far as authn-kinit is concerned: discovery, a
// token endpoint that checks the private_key_jwt, and /kerberos/tgt.
type fakeProvider struct {
	srv      *httptest.Server
	pub      any
	cred     []byte
	gotToken string
	assertAs string
}

func newFakeProvider(t *testing.T, pub any, cred []byte) *fakeProvider {
	t.Helper()
	p := &fakeProvider{pub: pub, cred: cred}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize", "token_endpoint": p.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("scope") != "kerberos" ||
			r.PostForm.Get("client_assertion_type") != assertionType || r.PostForm.Get("client_secret") != "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		jws := r.PostForm.Get("client_assertion")
		ok := func() (ok bool) {
			defer func() {
				if recover() != nil {
					ok = false
				}
			}()
			parts := strings.Split(jws, ".")
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			signed := []byte(parts[0] + "." + parts[1])
			switch k := p.pub.(type) {
			case *ecdsa.PublicKey:
				d := sha256.Sum256(signed)
				return ecdsa.Verify(k, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
			case ed25519.PublicKey:
				return ed25519.Verify(k, signed, sig)
			}
			return false
		}()
		if !ok {
			http.Error(w, "invalid_client", http.StatusUnauthorized)
			return
		}
		p.assertAs = r.PostForm.Get("client_id")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-" + p.assertAs, "token_type": "Bearer", "expires_in": 300, "scope": "kerberos"})
	})
	mux.HandleFunc("/kerberos/tgt", func(w http.ResponseWriter, r *http.Request) {
		p.gotToken = r.Header.Get("Authorization")
		if r.Method != http.MethodPost || p.gotToken != "Bearer tok-winpc-17" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Write(p.cred)
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// makeCred builds a KRB-CRED as go-authn/kdc's Mint does: one ticket, an
// unencrypted EncKrbCredPart.
func makeCred(t *testing.T, end time.Time, etype int32, withKey bool) []byte {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry("krbtgt/EXAMPLE.ORG", "EXAMPLE.ORG", "k", time.Now(), 2, 18); err != nil {
		t.Fatal(err)
	}
	krbtgt := types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", "EXAMPLE.ORG"}}
	cname := types.PrincipalName{NameType: 1, NameString: []string{"alice@univ.example"}}
	fl := types.NewKrbFlags()
	types.SetFlag(&fl, flags.Initial)
	types.SetFlag(&fl, flags.PreAuthent)
	start := end.Add(-time.Hour)
	tkt, sk, err := messages.NewTicket(cname, "EXAMPLE.ORG", krbtgt, "EXAMPLE.ORG", fl, kt, 18, 2, start, start, end, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !withKey {
		sk.KeyValue = nil
	}
	type info struct {
		Key       types.EncryptionKey `asn1:"explicit,tag:0"`
		PRealm    string              `asn1:"generalstring,explicit,tag:1"`
		PName     types.PrincipalName `asn1:"explicit,tag:2"`
		Flags     asn1.BitString      `asn1:"explicit,tag:3"`
		AuthTime  time.Time           `asn1:"generalized,explicit,tag:4"`
		StartTime time.Time           `asn1:"generalized,explicit,tag:5"`
		EndTime   time.Time           `asn1:"generalized,explicit,tag:6"`
		SRealm    string              `asn1:"generalstring,explicit,tag:8"`
		SName     types.PrincipalName `asn1:"explicit,tag:9"`
	}
	type encPart struct {
		Info []info `asn1:"explicit,tag:0"`
	}
	seq, err := asn1.Marshal(encPart{Info: []info{{sk, "EXAMPLE.ORG", cname, fl, start, start, end, "EXAMPLE.ORG", krbtgt}}})
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := tkt.Marshal()
	enc, _ := asn1.Marshal(types.EncryptedData{EType: etype, Cipher: derTLV(0x7d, seq)})
	ctx := func(n byte, b []byte) []byte { return derTLV(0xa0|n, b) }
	body := append(ctx(0, derTLV(0x02, []byte{5})), ctx(1, derTLV(0x02, []byte{22}))...)
	body = append(body, ctx(2, derTLV(0x30, tb))...)
	body = append(body, ctx(3, enc)...)
	return derTLV(0x76, derTLV(0x30, body))
}

func derTLV(tag byte, c []byte) []byte {
	n := len(c)
	var l []byte
	switch {
	case n < 0x80:
		l = []byte{byte(n)}
	case n < 0x100:
		l = []byte{0x81, byte(n)}
	default:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	}
	return append(append([]byte{tag}, l...), c...)
}

func TestDescribeCred(t *testing.T) {
	now := time.Now()
	info, err := describeCred(makeCred(t, now.Add(8*time.Hour), 0, true), now)
	if err != nil {
		t.Fatal(err)
	}
	if info.Client != "alice@univ.example" || info.Realm != "EXAMPLE.ORG" || info.Service != "krbtgt/EXAMPLE.ORG" {
		t.Errorf("%+v", info)
	}
	for name, b := range map[string][]byte{
		"an expired ticket":   makeCred(t, now.Add(-time.Minute), 0, true),
		"an encrypted part":   makeCred(t, now.Add(time.Hour), 18, true),
		"no session key":      makeCred(t, now.Add(time.Hour), 0, false),
		"garbage":             []byte("hello"),
		"a truncated message": makeCred(t, now.Add(time.Hour), 0, true)[:60],
		"nothing":             nil,
	} {
		if _, err := describeCred(b, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFetchTGT(t *testing.T) {
	cred := makeCred(t, time.Now().Add(time.Hour), 0, true)
	p := newFakeProvider(t, nil, cred)
	got, err := fetchTGT(context.Background(), http.DefaultClient, p.srv.URL, "tok-winpc-17")
	if err != nil || !bytes.Equal(got, cred) {
		t.Fatalf("%v", err)
	}
	if _, err := fetchTGT(context.Background(), http.DefaultClient, p.srv.URL, "tok-other"); err == nil {
		t.Error("a refusal was taken for a ticket")
	}
	// A redirect is not followed: the token would go where the issuer did not say.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("the redirect was followed") }))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer redir.Close()
	if _, err := fetchTGT(context.Background(), http.DefaultClient, redir.URL, "x"); err == nil {
		t.Error("a redirect answered as a ticket")
	}
	// Plain http to anything but loopback: the key is in the answer.
	if _, err := fetchTGT(context.Background(), http.DefaultClient, "http://login.example.org", "x"); err == nil {
		t.Error("http accepted for a remote issuer")
	}
}

func TestMachineTokenAndCommand(t *testing.T) {
	dir := t.TempDir()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyFile := writeKey(t, dir, ec)
	cred := makeCred(t, time.Now().Add(9*time.Hour), 0, true)
	p := newFakeProvider(t, &ec.PublicKey, cred)

	tok, err := machineToken(context.Background(), http.DefaultClient, p.srv.URL, "winpc-17", keyFile, "k1")
	if err != nil || tok != "tok-winpc-17" {
		t.Fatalf("%q %v", tok, err)
	}
	// Another machine's key: refused by the provider, so refused here.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := machineToken(context.Background(), http.DefaultClient, p.srv.URL, "winpc-17", writeKey(t, t.TempDir(), other), "k1"); err == nil {
		t.Error("a key the provider does not hold got a token")
	}

	// The command, end to end, writing the credential instead of loading it
	// (and loading it too, where that is possible -- not in this test).
	out := filepath.Join(dir, "tgt.kirbi")
	var buf bytes.Buffer
	cmd := RootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--issuer", p.srv.URL, "--client", "winpc-17", "--machine-key", keyFile, "--kid", "k1", "--cred-file", out, "--no-inject"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}
	b, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(b, cred) {
		t.Errorf("the credential file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v, want 0600", st.Mode().Perm())
		}
	}
	if !strings.Contains(buf.String(), "krbtgt/EXAMPLE.ORG for alice@univ.example@EXAMPLE.ORG") {
		t.Errorf("the summary:\n%s", buf.String())
	}

	// Nothing to do with the ticket: refused before anything is asked.
	cmd = RootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--issuer", p.srv.URL, "--client", "winpc-17", "--machine-key", keyFile, "--no-inject"})
	if err := cmd.Execute(); err == nil {
		t.Error("a run with nowhere to put the ticket succeeded")
	}
	cmd = RootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Error("a run with no issuer succeeded")
	}

	// A credential file that cannot be written is an error, not a success
	// that says "wrote".
	buf.Reset()
	cmd = RootCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--issuer", p.srv.URL, "--client", "winpc-17", "--machine-key", keyFile, "--kid", "k1", "--cred-file", filepath.Join(dir, "no", "such", "dir", "t.kirbi"), "--no-inject"})
	if err := cmd.Execute(); err == nil || strings.Contains(buf.String(), "wrote ") {
		t.Errorf("an unwritable credential file: %v\n%s", err, buf.String())
	}
}

func TestKeygen(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "machine.key")
	var out, errb bytes.Buffer
	cmd := RootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs([]string{"keygen", "--out", key, "--kid", "k1"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(out.Bytes(), &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("%v\n%s", err, out.String())
	}
	k := set.Keys[0]
	if k["kty"] != "EC" || k["crv"] != "P-256" || k["kid"] != "k1" || k["alg"] != "ES256" || k["d"] != "" {
		t.Errorf("jwk %v (a private member would be a leak)", k)
	}
	// The key it wrote signs what the JWK verifies.
	priv, alg, err := loadMachineKey(key)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := base64.RawURLEncoding.DecodeString(k["x"])
	y, _ := base64.RawURLEncoding.DecodeString(k["y"])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	jws, _ := clientAssertion(priv, alg, "k1", "c", "https://x", time.Now())
	verifyJWS(t, jws, pub)

	// Never overwritten.
	cmd = RootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs([]string{"keygen", "--out", key, "--kid", "k1"})
	if err := cmd.Execute(); err == nil {
		t.Error("an existing key was overwritten")
	}
}

func TestKsetupPlan(t *testing.T) {
	plan, err := ksetupPlan("EXAMPLE.ORG", "kdc.example.org", []string{"fs.example.org", "fs2.example.org"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ksetup /addkdc EXAMPLE.ORG kdc.example.org",
		"ksetup /addhosttorealmmap fs.example.org EXAMPLE.ORG",
		"ksetup /addhosttorealmmap fs2.example.org EXAMPLE.ORG",
	}
	if len(plan) != len(want) {
		t.Fatalf("%v", plan)
	}
	for i, c := range plan {
		if strings.Join(c, " ") != want[i] {
			t.Errorf("%d: %q, want %q", i, strings.Join(c, " "), want[i])
		}
	}
	undo, _ := ksetupPlan("EXAMPLE.ORG", "kdc.example.org", []string{"fs.example.org"}, true)
	if len(undo) != 2 || undo[0][1] != "/delhosttorealmmap" || undo[1][1] != "/delkdc" {
		t.Errorf("undo %v", undo)
	}
	// Names that are not names never reach a command.
	for _, bad := range []struct{ realm, kdc, host string }{
		{"example.org", "kdc", "fs"},        // a realm is in capitals
		{"EXAMPLE.ORG", "kdc & calc", "fs"}, // a shell word
		{"EXAMPLE.ORG", "kdc", "fs; del *"},
		{"EXAMPLE.ORG", "kdc", "-x"},
		{"EXAMPLE.ORG", "", "fs"},
	} {
		if _, err := ksetupPlan(bad.realm, bad.kdc, []string{bad.host}, false); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if _, err := ksetupPlan("EXAMPLE.ORG", "kdc", nil, false); err == nil {
		t.Error("no host accepted")
	}

	var out bytes.Buffer
	cmd := RootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"setup", "--print", "--realm", "EXAMPLE.ORG", "--kdc", "kdc.example.org", "--host", "fs.example.org"})
	if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), "ksetup /addkdc EXAMPLE.ORG kdc.example.org") {
		t.Errorf("%v\n%s", err, out.String())
	}
}
