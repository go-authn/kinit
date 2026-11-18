// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/messages"
)

// fetchTGT asks the provider for a TGT for the person (or machine) the access
// token is about, and returns the KRB-CRED (RFC 4120 5.8).
func fetchTGT(ctx context.Context, hc *http.Client, issuer, access string) ([]byte, error) {
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "https" && !isLoopback(u.Hostname())) {
		// The answer holds a session key in the clear: https, or a loopback
		// test provider, nothing else.
		return nil, fmt.Errorf("issuer %q: an https URL", issuer)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(issuer, "/")+"/kerberos/tgt", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	// A redirect would carry the token somewhere the issuer did not name.
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, httpError("the provider issued no ticket", resp)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// credInfo is what a KRB-CRED says about its one ticket.
type credInfo struct {
	Client, Realm, Service string
	Start, End             time.Time
}

// describeCred parses a KRB-CRED and refuses one this tool cannot use: not
// one ticket, an encrypted EncKrbCredPart (the provider sends etype 0 over
// TLS; anything else is not what it was told to expect), no session key, or a
// ticket already over.
func describeCred(b []byte, now time.Time) (credInfo, error) {
	var k messages.KRBCred
	if err := k.Unmarshal(b); err != nil {
		return credInfo{}, fmt.Errorf("not a KRB-CRED: %w", err)
	}
	if len(k.Tickets) != 1 {
		return credInfo{}, fmt.Errorf("%d tickets, want one", len(k.Tickets))
	}
	if k.EncPart.EType != 0 {
		return credInfo{}, fmt.Errorf("the credential part is encrypted (etype %d); only etype 0 is accepted", k.EncPart.EType)
	}
	var part messages.EncKrbCredPart
	if err := part.Unmarshal(k.EncPart.Cipher); err != nil {
		return credInfo{}, fmt.Errorf("EncKrbCredPart: %w", err)
	}
	if len(part.TicketInfo) != 1 {
		return credInfo{}, errors.New("the ticket information does not match the ticket")
	}
	ti := part.TicketInfo[0]
	if len(ti.Key.KeyValue) == 0 {
		return credInfo{}, errors.New("no session key")
	}
	if !ti.EndTime.After(now) {
		return credInfo{}, fmt.Errorf("the ticket ended at %s", ti.EndTime.Format(time.RFC3339))
	}
	return credInfo{
		Client: ti.PName.PrincipalNameString(), Realm: ti.PRealm,
		Service: ti.SName.PrincipalNameString(),
		Start:   ti.StartTime, End: ti.EndTime,
	}, nil
}
