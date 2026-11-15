// Package oauth signs in in the browser with PKCE.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/hushsecurity/hush-cli/internal/config"
	"github.com/hushsecurity/hush-cli/internal/httpx"
	"github.com/hushsecurity/hush-cli/internal/version"
)

const signInTimeout = 5 * time.Minute

// Registration is a registered public client and its loopback redirect.
type Registration struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func RequestToken(endpoint string, form url.Values) (*Token, error) {
	resp, err := httpx.Client.PostForm(endpoint, form)
	if err != nil {
		return nil, err
	}
	var tok Token
	return &tok, httpx.Decode(resp, &tok)
}

// listen binds the loopback port of the saved redirect URI, else any free one.
func listen(redirectURI string) (net.Listener, error) {
	if u, err := url.Parse(redirectURI); err == nil && u.Host != "" {
		if ln, err := net.Listen("tcp", u.Host); err == nil {
			return ln, nil
		}
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

func register(endpoint, redirectURI string) (string, error) {
	var out struct {
		ClientID string `json:"client_id"`
	}
	err := httpx.PostJSON(endpoint, map[string]any{
		"client_name":                "Hush CLI",
		"software_id":                "hush-cli",
		"software_version":           version.Version,
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
	}, &out)
	return out.ClientID, err
}

// SignIn runs a PKCE sign-in in the browser. It reuses c's redirect
// port when free, so one client serves every sign-in, else registers anew.
func SignIn(c *Registration, authorizeURL, tokenURL, registerURL string, params url.Values, tell func(authURL string)) (*Token, error) {
	ln, err := listen(c.RedirectURI)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ln.Close() }()
	redirectURI := fmt.Sprintf("http://%s/callback", ln.Addr())
	if c.ClientID == "" || c.RedirectURI != redirectURI {
		if c.ClientID, err = register(registerURL, redirectURI); err != nil {
			return nil, err
		}
		c.RedirectURI = redirectURI
	}

	verifier, state := random(), random()
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	maps.Copy(q, params)
	authURL, err := url.Parse(authorizeURL)
	if err != nil {
		return nil, err
	}
	maps.Copy(q, authURL.Query())
	authURL.RawQuery = q.Encode()
	tell(authURL.String())
	_ = OpenBrowser(authURL.String())

	code, err := waitForCode(ln, state)
	if err != nil {
		return nil, err
	}
	// Locked only now, not across the browser wait.
	if err := config.Lock(); err != nil {
		return nil, err
	}
	return RequestToken(tokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"client_id":     {c.ClientID},
	})
}

// waitForCode serves the redirect and returns the authorization code.
func waitForCode(ln net.Listener, state string) (string, error) {
	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if q.Get("state") != state { // not this sign-in's redirect
			http.Error(w, "unexpected sign-in redirect", http.StatusBadRequest)
			return
		}
		res := result{code: q.Get("code")}
		if res.code == "" {
			reason := q.Get("error")
			if d := q.Get("error_description"); d != "" {
				reason += ": " + d
			}
			res.err = errors.New("sign-in failed: " + reason)
			w.WriteHeader(http.StatusBadRequest)
			page(w, "Sign-in failed", reason+". Return to the terminal.")
		} else {
			page(w, "Signed in to Hush", "You can close this tab.")
		}
		select {
		case done <- res:
		default:
		}
	})
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	select {
	case res := <-done:
		return res.code, res.err
	case <-time.After(signInTimeout):
		return "", errors.New("timed out waiting for the browser sign-in")
	}
}

// The logo is linked, not bundled; offline it just doesn't show.
const logo = "https://www.hush.security/wp-content/uploads/2026/10/hush-icon-color-150x150.png"

// page shows a short message in the browser tab.
func page(w http.ResponseWriter, title, msg string) {
	_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%[1]s</title><link rel="icon" href="%[3]s">
<body style="font-family:system-ui,sans-serif;text-align:center;margin-top:20vh">
<img src="%[3]s" alt="" width="64"><h2>%[1]s</h2><p>%[2]s</p></body>`,
		html.EscapeString(title), html.EscapeString(msg), logo)
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

var OpenBrowser = func(u string) error { // a variable so tests can sign in without one
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	}
	return exec.Command("xdg-open", u).Start()
}
