// Command cofide drives github.com/cofide/wimse-s2s-httpsig-poc at its pinned
// commit for the visado WIMSE interop run. Both commands read `wimse mint`
// output made at the current time (the PoC and its RFC 9421 library check
// `created` against the wall clock).
//
//	cofide sign < mint     requests signed with the PoC's signer, as `wimse verify` input
//	cofide verify < mint   the PoC server's check on visado's signed requests
//
// The PoC's client and server fetch WIT-SVIDs from minispire, so the steps
// around the signer and verifier are reproduced here from
// wimse/client/client.go getHttp and wimse/server/server.go getHttp.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cofide/wimse-s2s-httpsig-poc/wimse/shared"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/yaronf/httpsign"
)

const (
	uri  = "https://tools.td.example/tickets?a=1"
	body = `{"title":"interop"}`
)

type mintCase struct {
	ID       string      `json:"id"`
	Kind     string      `json:"kind"`
	Mutation string      `json:"mutation"`
	Expect   string      `json:"expect"`
	SigExp   string      `json:"sig_expect"`
	Method   string      `json:"method"`
	URI      string      `json:"uri"`
	Headers  [][2]string `json:"headers"`
	Body     string      `json:"body"`
	WIT      string      `json:"wit"`
}

type mintOutput struct {
	Now    int64 `json:"now"`
	Suites []struct {
		Suite   string          `json:"suite"`
		Issuers json.RawMessage `json:"issuers"`
		Pop     jose.JSONWebKey `json:"pop_private_jwk"`
		Cases   []mintCase      `json:"cases"`
	} `json:"suites"`
}

func main() {
	var in mintOutput
	var out any
	err := json.NewDecoder(os.Stdin).Decode(&in)
	if err == nil {
		switch strings.Join(os.Args[1:], " ") {
		case "sign":
			out, err = sign(&in)
		case "verify":
			out, err = verify(&in)
		default:
			err = fmt.Errorf("usage: cofide <sign | verify> < mint.json")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cofide:", err)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func verdict(err error) map[string]any {
	if err != nil {
		return map[string]any{"verdict": "reject", "error": err.Error()}
	}
	return map[string]any{"verdict": "accept"}
}

// judged is verdict with whether it matches expect.
func judged(err error, expect string) map[string]any {
	v := verdict(err)
	v["agrees"] = v["verdict"] == expect
	return v
}

func newRequest(method, target, payload string, headers [][2]string) (*http.Request, error) {
	req, err := http.NewRequest(method, target, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	for _, h := range headers {
		req.Header.Add(h[0], h[1])
	}
	return req, nil
}

// sign signs a POST with the es256 suite's WIT and key, the way the PoC
// client does: the components of client.go getHttp, then
// shared.GetWITHTTPSigner with a nonce and the WIT's exp as expires.
func sign(in *mintOutput) (any, error) {
	for _, suite := range in.Suites {
		if suite.Suite != "es256" {
			continue
		}
		var wit string
		for _, c := range suite.Cases {
			if c.ID == "es256/httpsig/valid" {
				wit = c.WIT
			}
		}
		priv, ok := suite.Pop.Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("es256 pop key is %T", suite.Pop.Key)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		key := base64.StdEncoding.EncodeToString(der)
		var cases []map[string]any
		for _, components := range []string{"poc", "draft-08"} {
			for _, mutation := range []string{"valid", "body_changed", "covered_header_changed", "signature_tampered"} {
				c, err := signOne(key, wit, components, mutation)
				if err != nil {
					return nil, fmt.Errorf("%s/%s: %w", components, mutation, err)
				}
				cases = append(cases, c)
			}
		}
		return map[string]any{
			"implementation": "github.com/cofide/wimse-s2s-httpsig-poc",
			"now":            time.Now().Unix(),
			"issuers":        suite.Issuers,
			"cases":          cases,
		}, nil
	}
	return nil, fmt.Errorf("no es256 suite")
}

func signOne(key, wit, components, mutation string) (map[string]any, error) {
	req, err := newRequest(http.MethodPost, uri, body, [][2]string{{"Content-Type", "application/json"}})
	if err != nil {
		return nil, err
	}
	digestBody := io.NopCloser(strings.NewReader(body))
	digest, err := httpsign.GenerateContentDigestHeader(&digestBody, []string{httpsign.DigestSha256})
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Workload-Identity-Token", wit)

	// client.go getHttp.
	signedHeaders := []string{"@method", "@request-target", "Workload-Identity-Token"}
	if req.Body != nil {
		signedHeaders = append(signedHeaders, "content-digest")
	}
	for _, header := range []string{"content-type", "authorization", "Txn-Token"} {
		if req.Header.Get(header) != "" {
			signedHeaders = append(signedHeaders, header)
		}
	}
	if components == "draft-08" {
		signedHeaders = []string{"@method", "@path", "@query", "workload-identity-token", "content-type", "content-digest"}
	}
	parsed, err := jwt.ParseSigned(wit, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	claims := jwt.Claims{}
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}
	nonce := fmt.Sprintf("cofide-%s-%s-9b1f04d2", components, mutation)
	signer, err := shared.GetWITHTTPSigner(key, signedHeaders, shared.WithNonce(nonce), shared.WithClaims(&claims))
	if err != nil {
		return nil, err
	}
	input, signature, err := httpsign.SignRequest("wimse", *signer, req)
	if err != nil {
		return nil, err
	}
	sent := body
	contentType := "application/json"
	switch mutation {
	case "body_changed":
		sent = `{"title":"swapped"}`
	case "covered_header_changed":
		contentType = "text/plain"
	case "signature_tampered":
		i := strings.Index(signature, ":") + 1
		c := byte('A')
		if signature[i] == 'A' {
			c = 'B'
		}
		signature = signature[:i] + string(c) + signature[i+1:]
	}
	return map[string]any{
		"id": "cofide/" + components + "/" + mutation, "mutation": mutation,
		// Under draft-ietf-wimse-http-signature-08 none of these is valid.
		"expect": "reject", "method": http.MethodPost, "uri": uri, "body": sent, "wit": wit,
		"headers": [][2]string{
			{"content-type", contentType},
			{"content-digest", digest},
			{"content-length", fmt.Sprint(len(sent))},
			{"signature-input", input},
			{"signature", signature},
		},
	}, nil
}

// verify runs, on each signed visado request, the PoC server's check
// (server.go getHttp: the WIT is decoded without verification, then
// @request-target and Workload-Identity-Token must be covered) and the same
// RFC 9421 library with the components draft-08 requires plus the
// Content-Digest check of RFC 9530.
func verify(in *mintOutput) (any, error) {
	var out []map[string]any
	for _, suite := range in.Suites {
		for _, c := range suite.Cases {
			if c.Kind != "httpsig" {
				continue
			}
			row := map[string]any{"id": c.ID, "expect": c.Expect, "sig_expect": c.SigExp}
			if suite.Suite == "es256" {
				row["poc_server"] = judged(pocServer(c), c.Expect)
			}
			row["httpsign_draft08"] = judged(draft08(c), c.SigExp)
			out = append(out, row)
		}
	}
	return map[string]any{"verifier": "github.com/cofide/wimse-s2s-httpsig-poc server check, github.com/yaronf/httpsign", "cases": out}, nil
}

func caseRequest(c mintCase) (*http.Request, error) {
	req, err := newRequest(c.Method, c.URI, c.Body, c.Headers)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Workload-Identity-Token", c.WIT)
	return req, nil
}

func pocServer(c mintCase) error {
	r, err := caseRequest(c)
	if err != nil {
		return err
	}
	token, err := jose.ParseSigned(r.Header.Get("workload-identity-token"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}
	var payload struct {
		Sub string `json:"sub"`
		Cnf struct {
			Jwk jose.JSONWebKey `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(token.UnsafePayloadWithoutVerification(), &payload); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	clientEcdsa, ok := payload.Cnf.Jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("cnf key is %T", payload.Cnf.Jwk.Key)
	}
	verifier, err := httpsign.NewP256Verifier(*clientEcdsa, httpsign.NewVerifyConfig().SetKeyID("wimse"),
		httpsign.Headers("@request-target", "Workload-Identity-Token"))
	if err != nil {
		return err
	}
	return httpsign.VerifyRequest("wimse", *verifier, r)
}

func draft08(c mintCase) error {
	r, err := caseRequest(c)
	if err != nil {
		return err
	}
	parts := strings.Split(c.WIT, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var payload struct {
		Cnf struct {
			Jwk jose.JSONWebKey `json:"jwk"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	config := httpsign.NewVerifyConfig().SetNotOlderThan(90 * time.Second).
		SetAllowedTags([]string{"wimse-workload-to-workload"})
	fields := httpsign.Headers("@method", "@path", "@query", "workload-identity-token", "content-type", "content-digest")
	var verifier *httpsign.Verifier
	switch key := payload.Cnf.Jwk.Key.(type) {
	case *ecdsa.PublicKey:
		verifier, err = httpsign.NewP256Verifier(*key, config, fields)
	case ed25519.PublicKey:
		verifier, err = httpsign.NewEd25519Verifier(key, config, fields)
	default:
		return fmt.Errorf("cnf key is %T", key)
	}
	if err != nil {
		return err
	}
	if err := httpsign.VerifyRequest("wimse", *verifier, r); err != nil {
		return err
	}
	received := io.NopCloser(bytes.NewReader([]byte(c.Body)))
	return httpsign.ValidateContentDigestHeader(r.Header.Values("Content-Digest"), &received, []string{httpsign.DigestSha256})
}
