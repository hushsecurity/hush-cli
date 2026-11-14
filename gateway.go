package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// mcpClient has no overall timeout: a tool call can wait on the user (consent).
var mcpClient = &http.Client{}

var errNotSignedIn = errors.New("not signed in")

// GatewayAuth is the saved sign-in to one gateway.
type GatewayAuth struct {
	OAuthClient
	TokenEndpoint string `json:"token_endpoint"`
	RefreshToken  string `json:"refresh_token,omitempty"`
}

func gatewayFile(gw string) string {
	u, _ := url.Parse(gw)
	return "gateways/" + strings.NewReplacer(":", "_", "/", "_").Replace(u.Host+u.Path) + ".json"
}

// proxy relays MCP messages between stdio and a gateway's streamable HTTP endpoint.
type proxy struct {
	url string

	mu      sync.Mutex
	token   string
	session string
	version string
	initMsg []byte // replayed when the gateway drops the session

	authMu sync.Mutex // one sign-in at a time
	initMu sync.Mutex // one re-initialize at a time
	outMu  sync.Mutex
	out    io.Writer
}

func gatewayProxy(gw string) error {
	u, err := url.Parse(gw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q is not an https gateway URL", gw)
	}
	return runProxy(gw, os.Stdin, os.Stdout)
}

func runProxy(gw string, in io.Reader, out io.Writer) error {
	p := &proxy{url: gw, out: out}
	ctx, cancel := context.WithCancel(context.Background())
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	var requests, stream sync.WaitGroup
	streaming := false
	for sc.Scan() {
		msg := bytes.Clone(bytes.TrimSpace(sc.Bytes()))
		if len(msg) == 0 {
			continue
		}
		var head struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(msg, &head)
		var id json.RawMessage // set for requests, which get a reply
		if head.Method != "" {
			logf("%s %s", head.Method, head.Params.Name)
			if string(head.ID) != "null" {
				id = head.ID
			}
		}
		switch {
		case head.Method == "initialize": // later requests need its session
			p.mu.Lock()
			p.initMsg = msg
			p.mu.Unlock()
			if p.handle(msg, id, true) && !streaming {
				streaming = true
				stream.Add(1)
				go func() {
					defer stream.Done()
					p.listenStream(ctx)
				}()
			}
		case id != nil: // requests run concurrently; a tool call can take long
			requests.Add(1)
			go func() {
				defer requests.Done()
				p.handle(msg, id, false)
			}()
		default: // notifications and responses keep their order
			p.handle(msg, nil, false)
		}
	}
	requests.Wait()
	cancel()
	stream.Wait()
	p.endSession()
	return sc.Err()
}

// handle sends one message; a request that fails gets a JSON-RPC error back.
func (p *proxy) handle(msg, id json.RawMessage, initialize bool) bool {
	replied := id == nil
	err := p.send(msg, initialize, func(m []byte) {
		replied = replied || isReplyTo(m, id)
		p.write(m)
	})
	if err == nil && !replied {
		err = errors.New("the gateway ended the reply early")
	}
	if err == nil {
		return true
	}
	logf("%v", err)
	if id != nil && !replied {
		type rpcError struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		reply, _ := json.Marshal(struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   rpcError        `json:"error"`
		}{"2.0", id, rpcError{-32603, err.Error()}})
		p.write(reply)
	}
	return false
}

// isReplyTo tells a response to request id from the gateway's own requests,
// which may reuse the same id.
func isReplyTo(msg, id json.RawMessage) bool {
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	return json.Unmarshal(msg, &m) == nil && m.Method == "" && bytes.Equal(bytes.TrimSpace(m.ID), bytes.TrimSpace(id))
}

func (p *proxy) send(msg []byte, initialize bool, sink func([]byte)) error {
	for attempt := 0; ; attempt++ {
		tok, session := p.state()
		resp, err := p.post(msg, tok, session, initialize)
		if err != nil {
			return err
		}
		switch {
		case attempt >= 2:
		case resp.StatusCode == http.StatusUnauthorized:
			meta := resourceMetadata(resp.Header.Get("WWW-Authenticate"))
			_ = resp.Body.Close()
			// A refreshed token refused too: sign in again.
			if err := p.authorize(tok, meta, attempt > 0); err != nil {
				return err
			}
			continue
		case resp.StatusCode == http.StatusNotFound && session != "" && !initialize:
			_ = resp.Body.Close()
			if err := p.reinitialize(session); err != nil {
				return err
			}
			continue
		}
		return p.relay(resp, initialize, sink)
	}
}

func (p *proxy) state() (tok, session string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.token, p.session
}

// reinitialize replays the client's initialize after the gateway dropped expired.
func (p *proxy) reinitialize(expired string) error {
	p.initMu.Lock()
	defer p.initMu.Unlock()
	p.mu.Lock()
	session, msg := p.session, p.initMsg
	p.mu.Unlock()
	if session != expired { // another request already did
		return nil
	}
	logf("session expired, starting a new one")
	if err := p.send(msg, true, func([]byte) {}); err != nil {
		return err
	}
	tok, session := p.state()
	resp, err := p.post([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), tok, session, false)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// listenStream relays what the gateway sends outside of replies, while it offers a stream.
func (p *proxy) listenStream(ctx context.Context) {
	for wait := time.Second; ; wait = min(2*wait, 30*time.Second) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
		if err != nil {
			return
		}
		p.headers(req)
		req.Header.Set("Accept", "text/event-stream")
		if resp, err := mcpClient.Do(req); err == nil {
			if resp.StatusCode == http.StatusMethodNotAllowed {
				_ = resp.Body.Close()
				return
			}
			if resp.StatusCode == http.StatusOK {
				wait = time.Second
				_ = p.relayEvents(resp.Body, p.write)
			}
			_ = resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (p *proxy) post(msg []byte, tok, session string, initialize bool) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	p.setHeaders(req, tok, session, initialize)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if version, method, name := modernHeaders(msg); version != "" {
		req.Header.Set("Mcp-Protocol-Version", version)
		req.Header.Set("Mcp-Method", method)
		if name != "" {
			req.Header.Set("Mcp-Name", headerValue(name))
		}
		p.mu.Lock()
		p.version = version // notifications carry no version of their own
		p.mu.Unlock()
	}
	return mcpClient.Do(req)
}

// modernHeaders reads what a 2026-07-28+ request (no initialize, version in
// _meta) must repeat in its headers: the version, the method and its name.
func modernHeaders(msg []byte) (version, method, name string) {
	var m struct {
		Method string `json:"method"`
		Params struct {
			Name   string `json:"name"`
			URI    string `json:"uri"`
			TaskID string `json:"taskId"`
			Meta   struct {
				Version string `json:"io.modelcontextprotocol/protocolVersion"`
			} `json:"_meta"`
		} `json:"params"`
	}
	if json.Unmarshal(msg, &m) != nil || m.Params.Meta.Version == "" {
		return "", "", ""
	}
	switch {
	case m.Method == "tools/call" || m.Method == "prompts/get":
		name = m.Params.Name
	case strings.HasPrefix(m.Method, "resources/"):
		name = m.Params.URI
	case strings.HasPrefix(m.Method, "tasks/"):
		name = m.Params.TaskID
	}
	return m.Params.Meta.Version, m.Method, name
}

// headerValue base64-encodes a value a header can't carry as is.
func headerValue(v string) string {
	plain := strings.Trim(v, " \t") == v && !strings.HasPrefix(v, "=?base64?")
	for _, c := range v {
		plain = plain && c >= 0x20 && c <= 0x7e
	}
	if plain {
		return v
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(v)) + "?="
}

func (p *proxy) headers(req *http.Request) {
	tok, session := p.state()
	p.setHeaders(req, tok, session, false)
}

func (p *proxy) setHeaders(req *http.Request, tok, session string, initialize bool) {
	req.Header.Set("User-Agent", "hush-cli/"+version)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if initialize { // a new session starts without the old one's headers
		return
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.version != "" {
		req.Header.Set("Mcp-Protocol-Version", p.version)
	}
}

// relay passes the gateway's reply (one JSON message, or an event stream) to sink.
func (p *proxy) relay(resp *http.Response, initialize bool, sink func([]byte)) error {
	defer func() { _ = resp.Body.Close() }()
	if err := checkStatus(resp); err != nil {
		return err
	}
	if initialize {
		p.mu.Lock()
		p.session = resp.Header.Get("Mcp-Session-Id")
		p.mu.Unlock()
		sink = p.keepVersion(sink)
	}
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return p.relayEvents(resp.Body, sink)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || len(bytes.TrimSpace(body)) == 0 {
		return err
	}
	sink(body)
	return nil
}

func (p *proxy) relayEvents(r io.Reader, sink func([]byte)) error {
	br := bufio.NewReader(r)
	var data []byte
	for {
		line, err := br.ReadBytes('\n')
		line = bytes.TrimRight(line, "\r\n")
		switch {
		case len(line) == 0 && len(data) > 0: // end of an event
			sink(data)
			data = nil
		case bytes.HasPrefix(line, []byte("data:")):
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" "))...)
		}
		if err == io.EOF {
			if len(data) > 0 {
				sink(data)
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// keepVersion notes the protocol version from the initialize result.
func (p *proxy) keepVersion(sink func([]byte)) func([]byte) {
	return func(msg []byte) {
		var r struct {
			Result struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"result"`
		}
		if json.Unmarshal(msg, &r) == nil && r.Result.ProtocolVersion != "" {
			p.mu.Lock()
			p.version = r.Result.ProtocolVersion
			p.mu.Unlock()
		}
		sink(msg)
	}
}

// write sends one message to the client; stdio framing is one message per line.
func (p *proxy) write(msg []byte) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, msg); err != nil {
		logf("dropped a message that isn't JSON: %v", err)
		return
	}
	buf.WriteByte('\n')
	p.outMu.Lock()
	defer p.outMu.Unlock()
	_, _ = p.out.Write(buf.Bytes())
}

func (p *proxy) endSession() {
	if _, session := p.state(); session == "" {
		return
	}
	req, err := http.NewRequest(http.MethodDelete, p.url, nil)
	if err != nil {
		return
	}
	p.headers(req)
	if resp, err := mcpClient.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

// authorize gets a new access token: from the saved refresh token, or by
// signing in in the browser. used is the token that was refused.
func (p *proxy) authorize(used, meta string, browser bool) error {
	p.authMu.Lock()
	defer p.authMu.Unlock()
	if tok, _ := p.state(); tok != used { // another request already did it
		return nil
	}
	var tok string
	var err error
	if !browser {
		tok, err = refreshGateway(p.url)
		var refused *statusError
		switch {
		case errors.As(err, &refused) && refused.code < 500: // the refresh token is no good
			logf("refresh failed, signing in again: %v", err)
		case err != nil && !errors.Is(err, errNotSignedIn):
			return err
		}
	}
	if browser || err != nil {
		if tok, err = signInGateway(p.url, meta); err != nil {
			return err
		}
	}
	p.mu.Lock()
	p.token = tok
	p.mu.Unlock()
	return nil
}

// refreshGateway trades the saved refresh token, under the lock other hush runs share.
func refreshGateway(gw string) (string, error) {
	if err := lockSession(); err != nil {
		return "", err
	}
	defer releaseLock()
	var a GatewayAuth
	if err := load(gatewayFile(gw), &a); err != nil {
		return "", err
	}
	if a.RefreshToken == "" {
		return "", errNotSignedIn
	}
	tok, err := tokenAt(a.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {a.RefreshToken},
		"client_id":     {a.ClientID},
	})
	if err != nil {
		return "", err
	}
	if tok.RefreshToken != "" {
		a.RefreshToken = tok.RefreshToken
		if err := save(gatewayFile(gw), a); err != nil {
			return "", err
		}
	}
	return tok.AccessToken, nil
}

// signInGateway finds the gateway's authorization server and signs in in the browser.
func signInGateway(gw, meta string) (string, error) {
	u, _ := url.Parse(gw)
	if meta == "" {
		meta = u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource" + u.Path
	}
	if err := checkHTTPS(meta); err != nil {
		return "", err
	}
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := getJSON(meta, &prm); err != nil {
		return "", err
	}
	if prm.Resource == "" {
		prm.Resource = gw
	}
	if r, err := url.Parse(prm.Resource); err != nil || r.Scheme != u.Scheme || r.Host != u.Host {
		return "", fmt.Errorf("the gateway's metadata names another resource: %s", prm.Resource)
	}
	if len(prm.AuthorizationServers) == 0 {
		return "", errors.New("the gateway names no authorization server")
	}
	var as struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		RegistrationEndpoint  string `json:"registration_endpoint"`
	}
	if err := checkHTTPS(prm.AuthorizationServers[0]); err != nil {
		return "", err
	}
	issuer, _ := url.Parse(prm.AuthorizationServers[0])
	asMeta := issuer.Scheme + "://" + issuer.Host + "/.well-known/oauth-authorization-server" + strings.TrimRight(issuer.Path, "/")
	if err := getJSON(asMeta, &as); err != nil {
		return "", err
	}
	for _, e := range []string{as.AuthorizationEndpoint, as.TokenEndpoint, as.RegistrationEndpoint} {
		if err := checkHTTPS(e); err != nil {
			return "", err
		}
	}

	var a GatewayAuth
	if err := load(gatewayFile(gw), &a); err != nil {
		return "", err
	}
	if a.TokenEndpoint != as.TokenEndpoint {
		a = GatewayAuth{TokenEndpoint: as.TokenEndpoint}
	}
	defer releaseLock()
	tok, err := browserSignIn(&a.OAuthClient, as.AuthorizationEndpoint, as.TokenEndpoint, as.RegistrationEndpoint,
		url.Values{"resource": {prm.Resource}}, func(authURL string) {
			logf("opening your browser to sign in to the gateway; if it doesn't open, visit:\n  %s\n"+
				"If your agent stops waiting, restart it after signing in.", authURL)
		})
	if err != nil {
		return "", err
	}
	a.RefreshToken = tok.RefreshToken
	return tok.AccessToken, save(gatewayFile(gw), a)
}

// checkHTTPS refuses a URL from the gateway's metadata unless it's https,
// so a gateway can't have the browser open anything else (loopback http is fine).
func checkHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err == nil && (u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")) {
		return nil
	}
	return fmt.Errorf("the gateway's metadata has a URL that isn't https: %q", raw)
}

var resourceMetadataRe = regexp.MustCompile(`resource_metadata="([^"]+)"`)

func resourceMetadata(header string) string {
	if m := resourceMetadataRe.FindStringSubmatch(header); m != nil {
		return m[1]
	}
	return ""
}

func getJSON(u string, v any) error {
	resp, err := httpClient.Get(u)
	if err != nil {
		return err
	}
	return decode(resp, v)
}

// logf writes to stderr; stdout carries the protocol.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "hush: "+format+"\n", args...)
}
