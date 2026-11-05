package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	defaultAPI   = "https://api.us.hush-security.com"
	sessionFile  = "session.json"
	loginTimeout = 5 * time.Minute
)

func login(api, org string) error {
	if api == "" {
		api = os.Getenv("HUSH_API_URL")
	}
	if api == "" {
		api = defaultAPI
	}
	api = strings.TrimRight(api, "/")

	var s Session
	if err := load(sessionFile, &s); err != nil {
		return err
	}
	if s.API != api {
		s = Session{API: api}
	}

	// Reuse the registered redirect port when it's free, so one client
	// (and one agent in Hush) serves every login.
	ln, err := listen(s.RedirectURI)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	redirectURI := fmt.Sprintf("http://%s/callback", ln.Addr())
	if s.ClientID == "" || s.RedirectURI != redirectURI {
		if s.ClientID, err = register(api, redirectURI); err != nil {
			return err
		}
		s.RedirectURI = redirectURI
	}

	verifier, state := random(), random()
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {s.ClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"resource":              {api + "/v1/me"},
	}
	if org != "" {
		q.Set("org_shortname", org)
	}
	authURL := api + "/v1/agents/oauth/authorize?" + q.Encode()
	fmt.Printf("Opening your browser to sign in. If it doesn't open, visit:\n\n  %s\n\n", authURL)
	_ = openBrowser(authURL)

	code, err := waitForCode(ln, state)
	if err != nil {
		return err
	}
	tok, err := requestToken(api, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	})
	if err != nil {
		return err
	}
	s.RefreshToken, s.Org = tok.RefreshToken, org
	if err := save(sessionFile, s); err != nil {
		return err
	}
	fmt.Println("Signed in.")
	return nil
}

func logout() error {
	path, err := configPath(sessionFile)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("Signed out.")
	return nil
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

func register(api, redirectURI string) (string, error) {
	var out struct {
		ClientID string `json:"client_id"`
	}
	err := postJSON(api+"/v1/agents/oauth/register", map[string]any{
		"client_name":                "Hush CLI",
		"software_id":                "hush-cli",
		"software_version":           version,
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
	}, &out)
	return out.ClientID, err
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
			res.err = fmt.Errorf("sign-in failed: %s %s", q.Get("error"), q.Get("error_description"))
			http.Error(w, res.err.Error(), http.StatusBadRequest)
		} else {
			_, _ = fmt.Fprintln(w, "You can close this tab and return to the terminal.")
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
	case <-time.After(loginTimeout):
		return "", errors.New("timed out waiting for the browser sign-in")
	}
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func openBrowser(u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	}
	return exec.Command("xdg-open", u).Start()
}
