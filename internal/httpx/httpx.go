// Package httpx has helpers for calling JSON HTTP APIs.
package httpx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var Client = &http.Client{Timeout: 60 * time.Second}

func GetJSON(u string, v any) error {
	resp, err := Client.Get(u)
	if err != nil {
		return err
	}
	return Decode(resp, v)
}

func PostJSON(u string, body, v any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := Client.Post(u, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	return Decode(resp, v)
}

func Decode(resp *http.Response, v any) error {
	defer func() { _ = resp.Body.Close() }()
	if err := CheckStatus(resp); err != nil {
		return err
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// StatusError is a refused HTTP request.
type StatusError struct {
	Code int
	msg  string
}

func (e *StatusError) Error() string { return e.msg }

func CheckStatus(resp *http.Response) error {
	if resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &StatusError{resp.StatusCode, fmt.Sprintf("%s %s: %s %s", resp.Request.Method,
		resp.Request.URL.Path, resp.Status, strings.TrimSpace(string(body)))}
}
