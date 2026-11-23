// Command witwpt drives github.com/strideynet/wit-wpt-go at its pinned commit
// for the visado WIMSE interop run.
//
//	witwpt mint             WITs minted by wit-wpt-go, as `wimse verify` input
//	witwpt verify < mint    wit-wpt-go's ValidateWPT on `wimse mint` cases
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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
	var out any
	var err error
	switch strings.Join(os.Args[1:], " ") {
	case "mint":
		out, err = mint()
	case "verify":
		out, err = verify(os.Stdin)
	default:
		err = fmt.Errorf("usage: witwpt <mint | verify>")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "witwpt:", err)
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

// judged is verdict with whether it matches expect.
func judged(err error, expect string) map[string]any {
	v := verdict(err)
	v["agrees"] = v["verdict"] == expect
	return v
}

func verdict(err error) map[string]any {
	if err != nil {
		return map[string]any{"verdict": "reject", "error": err.Error()}
	}
	return map[string]any{"verdict": "accept"}
}

// tamper changes the first character of the JWS signature.
func tamper(token string) string {
	i := strings.LastIndex(token, ".") + 1
	c := byte('A')
	if token[i] == 'A' {
		c = 'B'
	}
	return token[:i] + string(c) + token[i+1:]
}

func kid(token string) string {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		panic(err)
	}
	return jws.Signatures[0].Header.KeyID
}

func mint() (any, error) {
	issuer, rogue := p256(0x61), p256(0x62)
	id := spiffeid.RequireFromString(caller)
	now := time.Now()
	wits := map[string]*witwpt.WIT{}
	for name, spec := range map[string]struct {
		key *ecdsa.PrivateKey
		exp time.Time
	}{
		"valid":   {issuer, now.Add(10 * time.Minute)},
		"other":   {issuer, now.Add(10 * time.Minute)},
		"expired": {issuer, now.Add(-10 * time.Minute)},
		"rogue":   {rogue, now.Add(10 * time.Minute)},
	} {
		wit, err := witwpt.MintWIT(spec.key, spec.exp, id)
		if err != nil {
			return nil, fmt.Errorf("MintWIT %s: %w", name, err)
		}
		wits[name] = wit
	}
	// MintWIT draws a fresh kid per token, so the issuer JWKS lists the
	// trusted key under each one. The rogue WIT's kid maps to the trusted key.
	var keys []any
	for _, name := range []string{"valid", "other", "expired", "rogue"} {
		keys = append(keys, jose.JSONWebKey{Key: issuer.Public(), KeyID: kid(wits[name].Signed), Algorithm: "ES256"})
	}
	_, mintErr := witwpt.MintWPT(wits["valid"], witwpt.WithAudience(aud), witwpt.WithExpiry(now.Add(time.Minute)))

	pop := func(w *witwpt.WIT) jose.JSONWebKey {
		return jose.JSONWebKey{Key: w.PrivateKey, Algorithm: "ES256"}
	}
	type row struct {
		mutation, expect string
		wit              *witwpt.WIT
		signed           string
		extra            map[string]any
	}
	rows := []row{
		{"valid", "accept", wits["valid"], wits["valid"].Signed, nil},
		{"expired_wit", "reject", wits["expired"], wits["expired"].Signed, nil},
		{"untrusted_issuer", "reject", wits["rogue"], wits["rogue"].Signed, nil},
		{"wit_signature_tampered", "reject", wits["valid"], tamper(wits["valid"].Signed), nil},
		{"wth_mismatch", "reject", wits["valid"], wits["valid"].Signed, map[string]any{"wpt_wit": wits["other"].Signed}},
		{"other_audience", "reject", wits["valid"], wits["valid"].Signed, map[string]any{"wpt_aud": otherAud}},
	}
	var cases []map[string]any
	for _, r := range rows {
		c := map[string]any{
			"id": "wit-wpt-go/" + r.mutation, "mutation": r.mutation, "expect": r.expect,
			"method": "GET", "uri": uri, "wit": r.signed, "pop_private_jwk": pop(r.wit),
		}
		for k, v := range r.extra {
			c[k] = v
		}
		cases = append(cases, c)
	}
	return map[string]any{
		"implementation": "github.com/strideynet/wit-wpt-go",
		"now":            now.Unix(),
		"mint_wpt":       mintResult(mintErr),
		"issuers": []any{map[string]any{
			"trust_domain": trustDomain,
			"jwks":         map[string]any{"keys": keys},
		}},
		"cases": cases,
	}, nil
}

type mintOutput struct {
	Suites []struct {
		Suite   string `json:"suite"`
		Issuers []struct {
			JWKS jose.JSONWebKeySet `json:"jwks"`
		} `json:"issuers"`
		Pop   jose.JSONWebKey `json:"pop_private_jwk"`
		Cases []struct {
			ID       string `json:"id"`
			Kind     string `json:"kind"`
			Mutation string `json:"mutation"`
			Expect   string `json:"expect"`
			WIT      string `json:"wit"`
			WPT      string `json:"wpt"`
		} `json:"cases"`
	} `json:"suites"`
}

func verify(r io.Reader) (any, error) {
	var in mintOutput
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, suite := range in.Suites {
		issuer := suite.Issuers[0].JWKS.Keys[0].Key
		edPop, isEd := suite.Pop.Key.(ed25519.PrivateKey)
		for _, c := range suite.Cases {
			if c.Kind != "wpt" {
				continue
			}
			_, _, err := witwpt.ValidateWPT(issuer, c.WIT, c.WPT)
			row := map[string]any{"id": c.ID, "expect": c.Expect, "as_is": judged(err, c.Expect)}
			if isEd {
				wpt, err := resign(c.WPT, edPop, c.Mutation == "wpt_signature_tampered")
				if err == nil {
					_, _, err = witwpt.ValidateWPT(issuer, c.WIT, wpt)
				}
				row["own_format_wpt"] = judged(err, c.Expect)
			}
			out = append(out, row)
		}
	}
	return map[string]any{"verifier": "github.com/strideynet/wit-wpt-go ValidateWPT", "cases": out}, nil
}

// resign re-signs the claims of a visado WPT in wit-wpt-go's own format
// (typ wimse-proof+jwt, alg EdDSA, exp as a JSON time), so only the WIT and
// the claim values are under test.
func resign(wpt string, key ed25519.PrivateKey, tampered bool) (string, error) {
	parts := strings.Split(wpt, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		JTI string `json:"jti"`
		WTH string `json:"wth"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Key: key, Algorithm: jose.EdDSA},
		(&jose.SignerOptions{}).WithType("wimse-proof+jwt"))
	if err != nil {
		return "", err
	}
	own := witwpt.WPT{Audience: claims.Aud, JTI: claims.JTI, Expiry: time.Unix(claims.Exp, 0), WTH: claims.WTH}
	signed, err := jwt.Signed(signer).Claims(own).Serialize()
	if err != nil {
		return "", err
	}
	if tampered {
		signed = tamper(signed)
	}
	return signed, nil
}

func mintResult(err error) map[string]any {
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true}
}
