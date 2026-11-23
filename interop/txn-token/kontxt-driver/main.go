// Command kontxt-driver drives aramase/kontxt's Transaction Token code.
//
//	kontxt-driver mint    prints tokens minted by pkg/token.New (RS256) and
//	                      the JWKS of pkg/keys.Manager, in the harness input
//	                      format. Uses the wall clock: token.New has no clock
//	                      parameter.
//	kontxt-driver verify  reads the harness input format on standard input,
//	                      serves its keys as a JWKS over a loopback listener
//	                      and verifies each case with sdk/verify.Verifier,
//	                      which also uses the wall clock.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
	"github.com/aramase/kontxt/sdk/verify"
)

const (
	trustDomain = "trust-domain.example"
	issuer      = "https://tts.trust-domain.example"
	lifetime    = 5 * time.Minute
)

type tcase struct {
	ID          string `json:"id"`
	Token       string `json:"token,omitempty"`
	Now         int64  `json:"now,omitempty"`
	TrustDomain string `json:"trust_domain,omitempty"`
	Expect      string `json:"expect,omitempty"`
	Why         string `json:"why,omitempty"`
}

type input struct {
	Minter      string            `json:"minter,omitempty"`
	TrustDomain string            `json:"trust_domain"`
	Issuer      string            `json:"issuer"`
	Now         int64             `json:"now"`
	Keys        []json.RawMessage `json:"keys"`
	Cases       []tcase           `json:"cases"`
	NotMinted   []tcase           `json:"not_minted,omitempty"`
}

type verdict struct {
	ID      string         `json:"id"`
	Verdict string         `json:"verdict"`
	Error   string         `json:"error,omitempty"`
	Tctx    map[string]any `json:"tctx,omitempty"`
	Rctx    map[string]any `json:"rctx,omitempty"`
}

func main() {
	var err error
	switch {
	case len(os.Args) == 2 && os.Args[1] == "mint":
		err = mint()
	case len(os.Args) == 2 && os.Args[1] == "verify":
		err = verifyCases()
	default:
		err = fmt.Errorf("usage: kontxt-driver <mint | verify>")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kontxt-driver:", err)
		os.Exit(2)
	}
}

func emit(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func claims() token.Claims {
	return token.Claims{
		Issuer:             issuer,
		Audience:           trustDomain,
		Subject:            "user@trust-domain.example",
		Scope:              "trade.stocks",
		RequestingWorkload: "spiffe://trust-domain.example/gateway",
		TransactionContext: map[string]any{
			"action": "BUY", "ticker": "MSFT", "quantity": "100",
			"customer_type": map[string]any{"geo": "US", "level": "VIP"},
		},
		RequesterContext: map[string]any{"req_ip": "198.51.100.7", "authn": "urn:ietf:rfc:6749"},
	}
}

func tamper(tok string) string {
	i := strings.LastIndexByte(tok, '.')
	sig, err := base64.RawURLEncoding.DecodeString(tok[i+1:])
	if err != nil || len(sig) == 0 {
		return tok
	}
	sig[0] ^= 0x01
	return tok[:i+1] + base64.RawURLEncoding.EncodeToString(sig)
}

func mint() error {
	km, err := keys.NewManager(2048, 0)
	if err != nil {
		return err
	}
	key, kid := km.SigningKey()
	now := time.Now()
	newToken := func(c token.Claims, life time.Duration) (string, error) {
		return token.New(c, key, kid, life)
	}

	valid, err := newToken(claims(), lifetime)
	if err != nil {
		return err
	}
	// token.New takes a lifetime, not an expiry: a negative one gives a token
	// that expired a minute before it was issued.
	expired, err := newToken(claims(), -time.Minute)
	if err != nil {
		return err
	}
	other := claims()
	other.Audience = "other-domain.example"
	wrongAud, err := newToken(other, lifetime)
	if err != nil {
		return err
	}

	var notMinted []tcase
	for _, missing := range []string{"scope", "req_wl", "sub", "iss"} {
		c := claims()
		switch missing {
		case "scope":
			c.Scope = ""
		case "req_wl":
			c.RequestingWorkload = ""
		case "sub":
			c.Subject = ""
		case "iss":
			c.Issuer = ""
		}
		_, err := newToken(c, lifetime)
		why := "minted"
		if err != nil {
			why = "token.New refused: " + err.Error()
		}
		notMinted = append(notMinted, tcase{ID: "rs256-missing-" + missing, Why: why})
	}

	rec := httptest.NewRecorder()
	km.JWKSHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		return err
	}

	return emit(input{
		Minter:      "kontxt",
		TrustDomain: trustDomain,
		Issuer:      issuer,
		Now:         now.Unix() + 1,
		Keys:        set.Keys,
		Cases: []tcase{
			{ID: "rs256-valid", Token: valid, Expect: "accept", Why: "§9.2 all REQUIRED claims, tctx and rctx"},
			{ID: "rs256-expired", Token: expired, Expect: "reject", Why: "§12.2 not expired"},
			{ID: "rs256-wrong-aud", Token: wrongAud, Expect: "reject", Why: "§9.2 aud, §12.2 trust domain"},
			{ID: "rs256-tampered", Token: tamper(valid), Expect: "reject", Why: "§12.2 signature"},
		},
		NotMinted: notMinted,
	})
}

func verifyCases() error {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		return err
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": in.Keys})
	}))
	defer srv.Close()

	out := []verdict{}
	for _, c := range in.Cases {
		domain := in.TrustDomain
		if c.TrustDomain != "" {
			domain = c.TrustDomain
		}
		v := verify.New(srv.URL, domain)
		claims, err := v.Verify(context.Background(), c.Token)
		if err != nil {
			out = append(out, verdict{ID: c.ID, Verdict: "reject", Error: err.Error()})
			continue
		}
		out = append(out, verdict{ID: c.ID, Verdict: "accept", Tctx: claims.TransactionContext, Rctx: claims.RequesterContext})
	}
	return emit(map[string]any{"verifier": "kontxt", "clock": "wall", "cases": out})
}
