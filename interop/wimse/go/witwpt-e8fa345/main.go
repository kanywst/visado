// Command witwpt-e8fa345 mints WITs and WPTs with
// github.com/strideynet/wit-wpt-go at e8fa345, the last commit whose MintWPT
// works (the next one switched the WIT key to P-256 but kept EdDSA for the
// WPT). Prints `wimse verify` input.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	witwpt "github.com/strideynet/wit-wpt-go"
)

const (
	trustDomain = "td.example"
	caller      = "spiffe://td.example/agent-a"
	uri         = "https://tools.td.example/tickets?status=open"
	aud         = "https://tools.td.example/tickets"
	otherAud    = "https://other.td.example/tickets"
)

func main() {
	out, err := mint()
	if err != nil {
		fmt.Fprintln(os.Stderr, "witwpt-e8fa345:", err)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func p256(b byte) *ecdsa.PrivateKey {
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), []byte(strings.Repeat(string(b), 32)))
	if err != nil {
		panic(err)
	}
	return key
}

func tamper(token string) string {
	i := strings.LastIndex(token, ".") + 1
	c := byte('A')
	if token[i] == 'A' {
		c = 'B'
	}
	return token[:i] + string(c) + token[i+1:]
}

func mint() (any, error) {
	issuer, rogue := p256(0x61), p256(0x62)
	id := spiffeid.RequireFromString(caller)
	now := time.Now()
	newWIT := func(key *ecdsa.PrivateKey, exp time.Time) (*witwpt.WIT, error) {
		return witwpt.MintWIT(key, exp, id)
	}
	newWPT := func(w *witwpt.WIT, audience string) (string, error) {
		wpt, err := witwpt.MintWPT(w, witwpt.WithAudience(audience), witwpt.WithExpiry(now.Add(time.Minute)))
		if err != nil {
			return "", err
		}
		return wpt.Signed, nil
	}
	valid, err := newWIT(issuer, now.Add(10*time.Minute))
	if err != nil {
		return nil, err
	}
	other, err := newWIT(issuer, now.Add(10*time.Minute))
	if err != nil {
		return nil, err
	}
	expired, err := newWIT(issuer, now.Add(-10*time.Minute))
	if err != nil {
		return nil, err
	}
	untrusted, err := newWIT(rogue, now.Add(10*time.Minute))
	if err != nil {
		return nil, err
	}
	type row struct {
		mutation, expect, wit string
		proofOf               *witwpt.WIT
		audience              string
	}
	rows := []row{
		{"valid", "accept", valid.Signed, valid, aud},
		{"expired_wit", "reject", expired.Signed, expired, aud},
		{"untrusted_issuer", "reject", untrusted.Signed, untrusted, aud},
		{"wth_mismatch", "reject", valid.Signed, other, aud},
		{"other_audience", "reject", valid.Signed, valid, otherAud},
		{"wpt_signature_tampered", "reject", valid.Signed, valid, aud},
	}
	var cases []map[string]any
	for _, r := range rows {
		wpt, err := newWPT(r.proofOf, r.audience)
		if err != nil {
			return nil, fmt.Errorf("MintWPT %s: %w", r.mutation, err)
		}
		if r.mutation == "wpt_signature_tampered" {
			wpt = tamper(wpt)
		}
		cases = append(cases, map[string]any{
			"id": "wit-wpt-go@e8fa345/" + r.mutation, "mutation": r.mutation, "expect": r.expect,
			"method": "GET", "uri": uri, "wit": r.wit, "wpt": wpt,
		})
	}
	// The same WIT with a WPT signed by visado-testkit, to tell the WIT and
	// the WPT apart.
	cases = append(cases, map[string]any{
		"id": "wit-wpt-go@e8fa345/valid+visado_wpt", "mutation": "none", "expect": "accept",
		"method": "GET", "uri": uri, "wit": valid.Signed,
		"pop_private_jwk": jose.JSONWebKey{Key: valid.PrivateKey, Algorithm: "EdDSA"},
	})
	return map[string]any{
		"implementation": "github.com/strideynet/wit-wpt-go@e8fa345",
		"now":            now.Unix(),
		"issuers": []any{map[string]any{
			"trust_domain": trustDomain,
			"jwks":         map[string]any{"keys": []any{jose.JSONWebKey{Key: issuer.Public(), Algorithm: "ES256"}}},
		}},
		"cases": cases,
	}, nil
}
