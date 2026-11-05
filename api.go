package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 60 * time.Second}

type token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Client calls the Hush API as the signed-in user.
type Client struct {
	api, accessToken string
}

// signedIn trades the saved refresh token for an access token. Refresh
// tokens are single use, so the new one is saved right away.
func signedIn() (*Client, error) {
	var s Session
	if err := load(sessionFile, &s); err != nil {
		return nil, err
	}
	if s.RefreshToken == "" {
		return nil, errors.New(`not signed in: run "hush login"`)
	}
	tok, err := requestToken(s.API, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {s.RefreshToken},
	})
	if err != nil {
		return nil, fmt.Errorf(`%w (run "hush login" to sign in again)`, err)
	}
	if tok.RefreshToken != "" {
		s.RefreshToken = tok.RefreshToken
		if err := save(sessionFile, s); err != nil {
			return nil, err
		}
	}
	return &Client{api: s.API, accessToken: tok.AccessToken}, nil
}

// claims reads the access token's claims, for display only.
func (c *Client) claims() map[string]any {
	claims := map[string]any{}
	if parts := strings.Split(c.accessToken, "."); len(parts) == 3 {
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(payload, &claims)
	}
	return claims
}

func requestToken(api string, form url.Values) (*token, error) {
	resp, err := httpClient.PostForm(api+"/v1/agents/oauth/token", form)
	if err != nil {
		return nil, err
	}
	var tok token
	return &tok, decode(resp, &tok)
}

func (c *Client) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.api+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	return httpClient.Do(req)
}

func (c *Client) getJSON(path string, v any) error {
	resp, err := c.get(path)
	if err != nil {
		return err
	}
	return decode(resp, v)
}

func postJSON(u string, body, v any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := httpClient.Post(u, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	return decode(resp, v)
}

func decode(resp *http.Response, v any) error {
	defer func() { _ = resp.Body.Close() }()
	if err := checkStatus(resp); err != nil {
		return err
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func checkStatus(resp *http.Response) error {
	if resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("%s %s: %s %s", resp.Request.Method, resp.Request.URL.Path,
		resp.Status, strings.TrimSpace(string(body)))
}
