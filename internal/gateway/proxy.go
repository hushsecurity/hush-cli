// Package gateway serves a Hush gateway to local agents over stdio.
package gateway

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
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

	"github.com/hushsecurity/hush-cli/internal/config"
	"github.com/hushsecurity/hush-cli/internal/httpx"
	"github.com/hushsecurity/hush-cli/internal/oauth"
	"github.com/hushsecurity/hush-cli/internal/version"
)

// mcpClient has no overall timeout: a tool call can wait on the user (consent).
var mcpClient = &http.Client{}

var (
	errNotSignedIn = errors.New("not signed in")
	errSignIn      = errors.New("not signed in to the Hush gateway")
)

// gatewayTools is what a gateway lists (without output schemas, which may
// change), offered while signed out: calling one signs in. Clients like Claude
// Desktop ignore list_changed, so the list mustn't change at sign-in.
//
//go:embed gateway_tools.json
var gatewayTools json.RawMessage

// Auth is the saved sign-in to one gateway.
type Auth struct {
	oauth.Registration
	TokenEndpoint string `json:"token_endpoint"`
	RefreshToken  string `json:"refresh_token,omitempty"`
}

const authDir = "gateways"

func authFile(gw string) string {
	u, _ := url.Parse(gw)
	return authDir + "/" + strings.NewReplacer(":", "_", "/", "_").Replace(u.Host+u.Path) + ".json"
}

// proxy relays MCP messages between stdio and a gateway's streamable HTTP endpoint.
type proxy struct {
	url string

	mu      sync.Mutex
	token   string
	session string
	version string
	initMsg []byte // replayed when the gateway drops the session
	// Signed out, the proxy answers the client itself, and the browser opens
	// only when a tool is called.
	signedOut bool
	meta      string // the gateway's resource metadata URL, for signing in
	signIns   int    // sign-ins tried, and the last one's error, for calls that waited on it
	signInErr error
	cancelled map[string]bool // ids of calls the client cancelled

	authMu   sync.Mutex // one token renewal at a time
	signInMu sync.Mutex // one sign-in at a time
	initMu   sync.Mutex // one re-initialize at a time
	outMu    sync.Mutex
	out      io.Writer

	ctx        context.Context
	stream     sync.WaitGroup
	streamOnce sync.Once
}

func Proxy(gw string) error {
	if err := checkGatewayURL(gw); err != nil {
		return err
	}
	return runProxy(gw, os.Stdin, os.Stdout)
}

func checkGatewayURL(gw string) error {
	if u, err := url.Parse(gw); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q is not an https gateway URL", gw)
	}
	return nil
}

func runProxy(gw string, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(context.Background())
	p := &proxy{url: gw, out: out, ctx: ctx, cancelled: map[string]bool{}}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	var requests sync.WaitGroup
	for sc.Scan() {
		msg := bytes.Clone(bytes.TrimSpace(sc.Bytes()))
		if len(msg) == 0 {
			continue
		}
		var head struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string          `json:"name"`
				RequestID json.RawMessage `json:"requestId"`
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
		if head.Method == "notifications/cancelled" && p.isSignedOut() {
			p.mu.Lock()
			p.cancelled[string(head.Params.RequestID)] = true
			p.mu.Unlock()
		}
		switch {
		case head.Method == "initialize": // later requests need its session
			p.mu.Lock()
			p.initMsg = msg
			p.mu.Unlock()
			if p.handle(msg, id, head.Method) {
				p.startStream()
			}
		case id != nil: // requests run concurrently; a tool call can take long
			requests.Add(1)
			go func() {
				defer requests.Done()
				p.handle(msg, id, head.Method)
			}()
		default: // notifications and responses keep their order
			p.handle(msg, nil, head.Method)
		}
	}
	requests.Wait()
	cancel()
	p.stream.Wait()
	p.endSession()
	return sc.Err()
}

func (p *proxy) startStream() {
	p.streamOnce.Do(func() {
		p.stream.Add(1)
		go func() {
			defer p.stream.Done()
			p.listenStream(p.ctx)
		}()
	})
}

// handle sends one message; a request that fails gets a JSON-RPC error back.
// Signed out, a tool call signs in first.
func (p *proxy) handle(msg, id json.RawMessage, method string) bool {
	triedSignIn := false
	var instructions string // the gateway's, which the client hasn't seen
	for {
		if p.isSignedOut() {
			if method != "tools/call" || triedSignIn {
				p.local(msg, id, method)
				return false
			}
			triedSignIn = true
			var err error
			if instructions, err = p.signIn(); err != nil {
				p.reply(id, toolResult("Couldn't sign in to the Hush gateway: "+err.Error(), true), nil)
				return false
			}
			p.mu.Lock()
			cancelled := p.cancelled[string(id)]
			delete(p.cancelled, string(id))
			p.mu.Unlock()
			if cancelled { // e.g. it timed out while the user signed in
				return false
			}
		}
		initialize := method == "initialize"
		replied := id == nil
		err := p.send(msg, initialize, func(m []byte) {
			if !replied && isReplyTo(m, id) {
				replied = true
				m = withText(m, instructions)
			}
			p.write(m)
		})
		if err == nil && !replied {
			err = errors.New("the gateway ended the reply early")
		}
		if err == nil {
			return true
		}
		if errors.Is(err, errSignIn) && !replied {
			continue // signed out now
		}
		logf("%v", err)
		if id != nil && !replied {
			p.reply(id, nil, err)
		}
		return false
	}
}

func (p *proxy) reply(id json.RawMessage, result any, err error) {
	type rpcError struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	r := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  any             `json:"result,omitempty"`
		Error   *rpcError       `json:"error,omitempty"`
	}{JSONRPC: "2.0", ID: id, Result: result}
	if err != nil {
		r.Error = &rpcError{-32603, err.Error()}
	}
	msg, _ := json.Marshal(r)
	p.write(msg)
}

// local answers the client while signed out.
func (p *proxy) local(msg, id json.RawMessage, method string) {
	if id == nil {
		return // notifications are dropped
	}
	listChanged := map[string]bool{"listChanged": true}
	var result any
	switch method {
	case "initialize":
		var m struct {
			Params struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"params"`
		}
		_ = json.Unmarshal(msg, &m)
		pv := m.Params.ProtocolVersion
		if pv == "" {
			pv = "2025-06-18"
		}
		result = map[string]any{
			"protocolVersion": pv,
			"capabilities":    map[string]any{"tools": listChanged, "prompts": listChanged, "resources": listChanged},
			"serverInfo":      map[string]string{"name": "hush", "version": version.Version},
			"instructions": "This server is the user's Hush gateway, which serves their organization's apps. " +
				"When the user asks for something from those apps, use its tools, starting with hush_list_apps. " +
				"If they aren't signed in yet, that first call opens the browser to sign in.",
		}
	case "ping":
		result = struct{}{}
	case "tools/list":
		result = gatewayTools
	case "prompts/list":
		result = map[string]any{"prompts": []any{}}
	case "resources/list":
		result = map[string]any{"resources": []any{}}
	case "resources/templates/list":
		result = map[string]any{"resourceTemplates": []any{}}
	case "tools/call": // reached only after a sign-in
		result = toolResult("The Hush gateway refused the new sign-in.", true)
	}
	if result == nil {
		p.reply(id, nil, errSignIn)
		return
	}
	p.reply(id, result, nil)
}

// withText adds text to a tool result's content.
func withText(msg []byte, text string) []byte {
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  map[string]any  `json:"result"`
	}
	d := json.NewDecoder(bytes.NewReader(msg))
	d.UseNumber()
	if text == "" || d.Decode(&m) != nil {
		return msg
	}
	content, ok := m.Result["content"].([]any)
	if !ok {
		return msg
	}
	m.Result["content"] = append(content, map[string]string{"type": "text", "text": text})
	out, err := json.Marshal(m)
	if err != nil {
		return msg
	}
	return out
}

func toolResult(text string, isError bool) any {
	return map[string]any{"isError": isError, "content": []any{map[string]string{"type": "text", "text": text}}}
}

// signIn takes up a newer sign-in another proxy saved, or signs in in the
// browser, then starts the client's session on the gateway and returns its
// instructions.
func (p *proxy) signIn() (instructions string, err error) {
	p.mu.Lock()
	tried := p.signIns
	p.mu.Unlock()
	p.signInMu.Lock()
	defer p.signInMu.Unlock()
	p.mu.Lock()
	waited, lastErr := p.signIns != tried, p.signInErr
	p.mu.Unlock()
	if waited { // on another call's sign-in: share its outcome, opening no second browser
		return "", lastErr
	}
	if !p.isSignedOut() {
		return "", nil
	}
	defer func() {
		p.mu.Lock()
		p.signIns, p.signInErr = p.signIns+1, err
		p.mu.Unlock()
	}()
	p.authMu.Lock()
	tok, err := refreshGateway(p.url)
	var bad *httpx.StatusError
	if errors.Is(err, errNotSignedIn) || errors.As(err, &bad) && bad.Code < 500 {
		p.mu.Lock()
		meta := p.meta
		p.mu.Unlock()
		tok, err = signInGateway(p.url, meta)
	}
	if err == nil {
		p.mu.Lock()
		p.token = tok
		p.mu.Unlock()
	}
	p.authMu.Unlock()
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	initMsg := p.initMsg
	p.mu.Unlock()
	if initMsg != nil {
		err := p.reinitialize("", func(m []byte) {
			var r struct {
				Result struct {
					Instructions string `json:"instructions"`
				} `json:"result"`
			}
			_ = json.Unmarshal(m, &r)
			instructions = r.Result.Instructions
		})
		if errors.Is(err, errSignIn) {
			return "", errors.New("the gateway refused the new sign-in")
		}
		if err != nil {
			return "", err
		}
		p.startStream()
	}
	p.mu.Lock()
	p.signedOut = false
	p.mu.Unlock()
	p.listChanged() // for clients that refresh the gateway's live list
	if instructions != "" {
		instructions = "The Hush gateway's instructions:\n" + instructions
	}
	return instructions, nil
}

// signOut drops a sign-in the gateway refused; the next tool call signs in again.
func (p *proxy) signOut(meta string) {
	p.mu.Lock()
	inSession := p.session != ""
	p.signedOut, p.meta, p.token, p.session = true, meta, "", ""
	p.mu.Unlock()
	logf("not signed in to the gateway; the next tool call signs in")
	if inSession {
		p.listChanged()
	}
}

func (p *proxy) isSignedOut() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signedOut
}

func (p *proxy) listChanged() {
	for _, list := range []string{"tools", "prompts", "resources"} {
		p.write([]byte(`{"jsonrpc":"2.0","method":"notifications/` + list + `/list_changed"}`))
	}
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
			// A refreshed token refused too: sign out.
			if err := p.authorize(tok, meta, attempt > 0); err != nil {
				return err
			}
			continue
		case resp.StatusCode == http.StatusNotFound && session != "" && !initialize:
			_ = resp.Body.Close()
			logf("session expired, starting a new one")
			if err := p.reinitialize(session, func([]byte) {}); err != nil {
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
func (p *proxy) reinitialize(expired string, sink func([]byte)) error {
	p.initMu.Lock()
	defer p.initMu.Unlock()
	p.mu.Lock()
	session, msg := p.session, p.initMsg
	p.mu.Unlock()
	if session != expired { // another request already did
		return nil
	}
	if err := p.send(msg, true, sink); err != nil {
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
		if p.isSignedOut() {
			wait = time.Second // poll nothing until signed back in
		} else if resp, err := mcpClient.Do(req); err == nil {
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
	req.Header.Set("User-Agent", "hush-cli/"+version.Version)
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
	if err := httpx.CheckStatus(resp); err != nil {
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

// authorize gets a new access token from the saved refresh token, or signs
// out. used is the token the gateway refused; refused, that a fresh one was.
func (p *proxy) authorize(used, meta string, refused bool) error {
	p.authMu.Lock()
	defer p.authMu.Unlock()
	if tok, _ := p.state(); tok != used { // another request already did it
		return nil
	}
	if p.isSignedOut() { // only a tool call signs back in
		return errSignIn
	}
	if !refused {
		tok, err := refreshGateway(p.url)
		var bad *httpx.StatusError
		switch {
		case err == nil:
			p.mu.Lock()
			p.token = tok
			p.mu.Unlock()
			return nil
		case errors.As(err, &bad) && bad.Code < 500: // the refresh token is no good
			logf("refresh failed: %v", err)
		case !errors.Is(err, errNotSignedIn):
			return err
		}
	}
	p.signOut(meta)
	return errSignIn
}

// refreshGateway trades the saved refresh token, under the lock other hush runs share.
func refreshGateway(gw string) (string, error) {
	if err := config.Lock(); err != nil {
		return "", err
	}
	defer config.ReleaseLock()
	var a Auth
	if err := config.Load(authFile(gw), &a); err != nil {
		return "", err
	}
	if a.RefreshToken == "" {
		return "", errNotSignedIn
	}
	tok, err := oauth.RequestToken(a.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {a.RefreshToken},
		"client_id":     {a.ClientID},
	})
	if err != nil {
		return "", err
	}
	if tok.RefreshToken != "" {
		a.RefreshToken = tok.RefreshToken
		if err := config.Save(authFile(gw), a); err != nil {
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
	if err := httpx.GetJSON(meta, &prm); err != nil {
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
	if err := httpx.GetJSON(asMeta, &as); err != nil {
		return "", err
	}
	for _, e := range []string{as.AuthorizationEndpoint, as.TokenEndpoint, as.RegistrationEndpoint} {
		if err := checkHTTPS(e); err != nil {
			return "", err
		}
	}

	var a Auth
	if err := config.Load(authFile(gw), &a); err != nil {
		return "", err
	}
	if a.TokenEndpoint != as.TokenEndpoint {
		a = Auth{TokenEndpoint: as.TokenEndpoint}
	}
	defer config.ReleaseLock()
	tok, err := oauth.SignIn(&a.Registration, as.AuthorizationEndpoint, as.TokenEndpoint, as.RegistrationEndpoint,
		url.Values{"resource": {prm.Resource}}, func(authURL string) {
			logf("opening your browser to sign in to the gateway; if it doesn't open, visit:\n  %s", authURL)
		})
	if err != nil {
		return "", err
	}
	a.RefreshToken = tok.RefreshToken
	return tok.AccessToken, config.Save(authFile(gw), a)
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

// logf writes to stderr; stdout carries the protocol.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "hush: "+format+"\n", args...)
}

func ForgetAll() error {
	if err := config.Lock(); err != nil {
		return err
	}
	path, err := config.Path(authDir)
	if err != nil {
		return err
	}
	return os.RemoveAll(path)
}
