// Command gospiffe validates the WITs of `wimse mint` output with
// github.com/spiffe/go-spiffe/v2/exp/svid/witsvid at its pinned commit.
// ParseAndValidate checks time against the wall clock, so mint at the
// current time (`wimse mint --now $(date +%s)`).
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type mintOutput struct {
	Suites []struct {
		Suite   string `json:"suite"`
		Issuers []struct {
			TrustDomain string          `json:"trust_domain"`
			JWKS        json.RawMessage `json:"jwks"`
		} `json:"issuers"`
		Cases []struct {
			ID        string `json:"id"`
			Kind      string `json:"kind"`
			WITExpect string `json:"wit_expect"`
			WIT       string `json:"wit"`
		} `json:"cases"`
	} `json:"suites"`
}

func main() {
	if len(os.Args) != 2 || os.Args[1] != "verify" {
		fmt.Fprintln(os.Stderr, "usage: gospiffe verify < mint.json")
		os.Exit(2)
	}
	var in mintOutput
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, "gospiffe:", err)
		os.Exit(2)
	}
	var out []map[string]any
	for _, suite := range in.Suites {
		issuer := suite.Issuers[0]
		td, err := spiffeid.TrustDomainFromString(issuer.TrustDomain)
		if err != nil {
			fmt.Fprintln(os.Stderr, "gospiffe:", err)
			os.Exit(2)
		}
		bundle, bundleErr := witbundle.Parse(td, issuer.JWKS)
		for _, c := range suite.Cases {
			// The httpsig cases reuse the WPT cases' WITs.
			if c.Kind != "wpt" {
				continue
			}
			row := map[string]any{"id": c.ID, "expect": c.WITExpect}
			err := bundleErr
			if err == nil {
				_, err = witsvid.ParseAndValidate(c.WIT, bundle)
			}
			if err != nil {
				row["verdict"], row["error"] = "reject", err.Error()
			} else {
				row["verdict"] = "accept"
			}
			row["agrees"] = row["verdict"] == c.WITExpect
			out = append(out, row)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"verifier": "github.com/spiffe/go-spiffe/v2/exp/svid/witsvid ParseAndValidate", "cases": out})
}
