// Package auth signs in to Hush and calls its API as the signed-in user.
package auth

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/hushsecurity/hush-cli/internal/config"
	"github.com/hushsecurity/hush-cli/internal/oauth"
)

const (
	DefaultAPI  = "https://api.us.hush-security.com"
	SessionFile = "session.json"
)

// Session is the saved sign-in.
type Session struct {
	API string `json:"api"`
	oauth.Registration
	RefreshToken string `json:"refresh_token,omitempty"`
	Org          string `json:"org,omitempty"` // the short name, when login was given it
}

func LoadSession() (Session, error) {
	var s Session
	return s, config.Load(SessionFile, &s)
}

func Login(api, org string) error {
	if api == "" {
		api = os.Getenv("HUSH_API_URL")
	}
	if api == "" {
		api = DefaultAPI
	}
	api = strings.TrimRight(api, "/")

	s, err := LoadSession()
	if err != nil {
		return err
	}
	if s.API != api {
		s = Session{API: api}
	}

	params := url.Values{"resource": {api + "/v1/me"}}
	if org != "" {
		params.Set("org_shortname", org)
	}
	o := api + "/v1/agents/oauth"
	tok, err := oauth.SignIn(&s.Registration, o+"/authorize", o+"/token", o+"/register", params, func(authURL string) {
		fmt.Printf("Opening your browser to sign in. If it doesn't open, visit:\n\n  %s\n\nWaiting for you to sign in…\n", authURL)
	})
	if err != nil {
		return err
	}
	s.RefreshToken, s.Org = tok.RefreshToken, org
	if err := config.Save(SessionFile, s); err != nil {
		return err
	}
	claims := (&Client{accessToken: tok.AccessToken}).Claims()
	orgName := org
	if orgName == "" {
		orgName = fmt.Sprint(claims["oid"])
	}
	fmt.Printf("Signed in as %s to %s.\n", UserName(claims), orgName)
	return nil
}

func Logout() error {
	if err := config.Lock(); err != nil {
		return err
	}
	path, err := config.Path(SessionFile)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// UserName shows the user as "Name <email>", or just the email.
func UserName(claims map[string]any) string {
	if name, ok := claims["name"].(string); ok && name != "" {
		return fmt.Sprintf("%s <%v>", name, claims["email"])
	}
	return fmt.Sprint(claims["email"])
}
