package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hushsecurity/hush-cli/internal/config"
	"github.com/hushsecurity/hush-cli/internal/httpx"
	"github.com/hushsecurity/hush-cli/internal/oauth"
)

// Client calls the Hush API as the signed-in user.
type Client struct {
	api, accessToken string
}

// SignedIn trades the saved refresh token for an access token. Refresh
// tokens are single use, so the new one is saved right away.
func SignedIn() (*Client, error) {
	if err := config.Lock(); err != nil {
		return nil, err
	}
	s, err := LoadSession()
	if err != nil {
		return nil, err
	}
	if s.RefreshToken == "" {
		return nil, errors.New(`not signed in: run "hush login"`)
	}
	tok, err := oauth.RequestToken(s.API+"/v1/agents/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {s.RefreshToken},
	})
	if err != nil {
		return nil, fmt.Errorf(`%w (run "hush login" to sign in again)`, err)
	}
	if tok.RefreshToken != "" {
		s.RefreshToken = tok.RefreshToken
		if err := config.Save(SessionFile, s); err != nil {
			return nil, err
		}
	}
	return &Client{api: s.API, accessToken: tok.AccessToken}, nil
}

func (c *Client) API() string { return c.api }

// Claims reads the access token's claims, for display only.
func (c *Client) Claims() map[string]any {
	claims := map[string]any{}
	if parts := strings.Split(c.accessToken, "."); len(parts) == 3 {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(payload, &claims)
	}
	return claims
}

func (c *Client) Get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.api+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	return httpx.Client.Do(req)
}

func (c *Client) GetJSON(path string, v any) error {
	resp, err := c.Get(path)
	if err != nil {
		return err
	}
	return httpx.Decode(resp, v)
}
