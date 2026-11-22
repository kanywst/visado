// Command atlas-verify verifies Transaction Tokens with atlas-go's
// VerifyTransactionToken. It reads the harness input format on standard input
// ({trust_domain, issuer, now, keys, cases: [{id, token, now?, trust_domain?}]})
// and prints one verdict per case.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	atlas "github.com/Atlas-Authorization/atlas-go"
)

type input struct {
	TrustDomain string            `json:"trust_domain"`
	Issuer      string            `json:"issuer"`
	Now         int64             `json:"now"`
	Keys        []json.RawMessage `json:"keys"`
	Cases       []struct {
		ID          string `json:"id"`
		Token       string `json:"token"`
		Now         int64  `json:"now"`
		TrustDomain string `json:"trust_domain"`
	} `json:"cases"`
}

type verdict struct {
	ID      string         `json:"id"`
	Verdict string         `json:"verdict"`
	Error   string         `json:"error,omitempty"`
	Tctx    map[string]any `json:"tctx,omitempty"`
	Rctx    map[string]any `json:"rctx,omitempty"`
}

func main() {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, "atlas-verify:", err)
		os.Exit(2)
	}
	jwks, err := json.Marshal(map[string]any{"keys": in.Keys})
	if err != nil {
		fmt.Fprintln(os.Stderr, "atlas-verify:", err)
		os.Exit(2)
	}
	out := []verdict{}
	for _, c := range in.Cases {
		now, domain := in.Now, in.TrustDomain
		if c.Now != 0 {
			now = c.Now
		}
		if c.TrustDomain != "" {
			domain = c.TrustDomain
		}
		res, err := atlas.VerifyTransactionToken(context.Background(), c.Token, atlas.TxnTokenOptions{
			Issuer:      in.Issuer,
			TrustDomain: domain,
			JWKSJSON:    jwks,
			Now:         time.Unix(now, 0),
		})
		if err != nil {
			out = append(out, verdict{ID: c.ID, Verdict: "reject", Error: err.Error()})
			continue
		}
		out = append(out, verdict{ID: c.ID, Verdict: "accept", Tctx: res.Claims.Tctx, Rctx: res.Claims.Rctx})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"verifier": "atlas-go", "cases": out}); err != nil {
		os.Exit(2)
	}
}
