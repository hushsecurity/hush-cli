package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGateway is an MCP endpoint that wants a bearer token, with its
// authorization server.
type fakeGateway struct {
	url string

	mu        sync.Mutex
	signIns   int
	tokens    int    // tokens issued
	at, rt    string // the valid access token, and the one refresh token that works
	sessions  int
	session   string               // the live one
	expire    bool                 // drop the session after the next tools/list
	stream    []string             // messages to send on the GET stream, once
	cut       bool                 // end tools/list streams before the reply
	resource  string               // metadata's resource, if not the gateway's
	authorize string               // metadata's authorization endpoint, if not ours
	answers   chan json.RawMessage // the client's answers to our requests
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{answers: make(chan json.RawMessage, 10)}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		switch r.URL.Path {
		case "/mcp":
			if g.at == "" || r.Header.Get("Authorization") != "Bearer "+g.at {
				w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+srv.URL+`/.well-known/oauth-protected-resource/mcp"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			g.serveMCP(w, r)
		case "/.well-known/oauth-protected-resource/mcp":
			resource := g.resource
			if resource == "" {
				resource = srv.URL + "/mcp"
			}
			fmt.Fprintf(w, `{"resource":"%s","authorization_servers":["%s/as"]}`, resource, srv.URL)
		case "/.well-known/oauth-authorization-server/as":
			authorize := g.authorize
			if authorize == "" {
				authorize = srv.URL + "/as/authorize"
			}
			fmt.Fprintf(w, `{"authorization_endpoint":"%s","token_endpoint":"%[2]s/token","registration_endpoint":"%[2]s/register"}`, authorize, srv.URL)
		case "/register":
			_, _ = w.Write([]byte(`{"client_id":"c1"}`))
		case "/as/authorize":
			q := r.URL.Query()
			if q.Get("resource") != srv.URL+"/mcp" || q.Get("client_id") != "c1" {
				http.Error(w, "bad authorize request", http.StatusBadRequest)
				return
			}
			g.signIns++
			http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {"code"}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
		case "/token":
			_ = r.ParseForm()
			if r.Form.Get("grant_type") == "refresh_token" && (g.rt == "" || r.Form.Get("refresh_token") != g.rt) {
				http.Error(w, "refresh token was already used", http.StatusBadRequest)
				return
			}
			g.tokens++ // single-use refresh tokens, and only the newest access token works
			g.at, g.rt = fmt.Sprintf("at%d", g.tokens), fmt.Sprintf("rt%d", g.tokens)
			_ = json.NewEncoder(w).Encode(token{AccessToken: g.at, RefreshToken: g.rt})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	g.url = srv.URL + "/mcp"

	home := t.TempDir()
	for _, env := range []string{"HOME", "USERPROFILE", "XDG_CONFIG_HOME", "AppData"} {
		t.Setenv(env, home)
	}
	orig := openBrowser
	openBrowser = followRedirect
	t.Cleanup(func() { openBrowser = orig })
	return g
}

// followRedirect is the "browser": it signs in and follows the redirect back.
func followRedirect(u string) error {
	go func() {
		if resp, err := http.Get(u); err == nil {
			_ = resp.Body.Close()
		}
	}()
	return nil
}

func (g *fakeGateway) serveMCP(w http.ResponseWriter, r *http.Request) {
	session := r.Header.Get("Mcp-Session-Id")
	if r.Method == http.MethodGet {
		if len(g.stream) == 0 || session != g.session {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, m := range g.stream {
			fmt.Fprintf(w, "data: %s\n\n", m)
		}
		g.stream = nil
		return
	}
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
	}
	_ = json.NewDecoder(r.Body).Decode(&msg)
	var tool struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(msg.Params, &tool)
	if v := r.Header.Get("Mcp-Protocol-Version"); v >= "2026-07-28" {
		serveModern(w, r, v, msg.ID, msg.Method, msg.Params)
		return
	}
	if msg.Method == "initialize" {
		if session != "" { // like the real gateway: a session header names an existing session
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		g.sessions++
		g.session = fmt.Sprintf("s%d", g.sessions)
		w.Header().Set("Mcp-Session-Id", g.session)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\n \"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"protocolVersion\":\"2025-06-18\"}}", msg.ID)
		return
	}
	switch {
	case session == "":
		http.Error(w, "session header is required", http.StatusBadRequest)
	case session != g.session:
		http.Error(w, "session not found", http.StatusNotFound)
	case r.Header.Get("Mcp-Protocol-Version") != "2025-06-18":
		http.Error(w, "missing protocol version", http.StatusBadRequest)
	case msg.Method == "tools/list":
		if g.expire {
			g.session, g.expire = "", false
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if g.cut {
			return
		}
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"tools\":[]}}\n\n", msg.ID)
	case msg.Method == "tools/call":
		g.mu.Unlock() // let other calls in while this one waits
		defer g.mu.Lock()
		g.callTool(w, msg.ID, tool.Name)
	case msg.Method == "" && msg.Result != nil: // the client answers our request
		g.answers <- msg.Result
		w.WriteHeader(http.StatusAccepted)
	case msg.Method != "" && msg.ID != nil: // other requests echo their params
		w.Header().Set("Content-Type", "application/json")
		params := msg.Params
		if params == nil {
			params = json.RawMessage("null")
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"echo":%s}}`, msg.ID, params)
	default:
		w.WriteHeader(http.StatusAccepted)
	}
}

// serveModern checks a 2026-07-28 request like the real gateway: no session,
// and headers that repeat the body's version, method and name. It echoes the params.
func serveModern(w http.ResponseWriter, r *http.Request, version string, id json.RawMessage, method string, params json.RawMessage) {
	var p struct {
		Name, URI string
		Meta      map[string]any `json:"_meta"`
	}
	_ = json.Unmarshal(params, &p)
	name := r.Header.Get("Mcp-Name")
	if v, ok := strings.CutPrefix(name, "=?base64?"); ok {
		b, _ := base64.StdEncoding.DecodeString(strings.TrimSuffix(v, "?="))
		name = string(b)
	}
	switch {
	case r.Header.Get("Mcp-Session-Id") != "":
		http.Error(w, "no sessions in this version", http.StatusBadRequest)
	case id == nil: // a notification: the header is its only version
		w.WriteHeader(http.StatusAccepted)
	case p.Meta["io.modelcontextprotocol/protocolVersion"] != version:
		http.Error(w, "version mismatch", http.StatusBadRequest)
	case r.Header.Get("Mcp-Method") != method:
		http.Error(w, "Mcp-Method mismatch", http.StatusBadRequest)
	case name != p.Name+p.URI:
		http.Error(w, "Mcp-Name mismatch", http.StatusBadRequest)
	default:
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"echo":%s}}`, id, params)
	}
}

// callTool behaves like gateway tools: consent asks the user mid-call (with
// our own request reusing the call's id), slow takes a while, big is 3MB.
func (g *fakeGateway) callTool(w http.ResponseWriter, id json.RawMessage, name string) {
	event := func(format string, args ...any) {
		fmt.Fprintf(w, "data: "+format+"\n\n", args...)
		w.(http.Flusher).Flush()
	}
	switch name {
	case "consent":
		w.Header().Set("Content-Type", "text/event-stream")
		event(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":1,"progress":1}}`)
		event(`{"jsonrpc":"2.0","id":%s,"method":"elicitation/create","params":{"message":"Allow?"}}`, id)
		select {
		case answer := <-g.answers:
			event(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":%q}]}}`, id, answer)
		case <-time.After(5 * time.Second):
		}
	case "slow":
		time.Sleep(time.Duration(rand.IntN(30)) * time.Millisecond)
		w.Header().Set("Content-Type", "text/event-stream")
		event(`{"jsonrpc":"2.0","id":%s,"result":{"content":[]}}`, id)
	case "odd": // SSE as servers may send it
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, ": keepalive\r\nretry: 1000\r\nid: 42\r\nevent: message\r\n"+
			"data: {\"jsonrpc\":\"2.0\",\"id\":%s,\r\ndata: \"result\":{\"content\":[]}}\r\n\r\n", id)
	case "fail":
		http.Error(w, "upstream exploded", http.StatusInternalServerError)
	case "iserror":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"isError":true,"content":[{"type":"text","text":"denied"}]}}`, id)
	case "askthencut": // our request reuses the call's id, then the stream ends
		w.Header().Set("Content-Type", "text/event-stream")
		event(`{"jsonrpc":"2.0","id":%s,"method":"elicitation/create","params":{"message":"Allow?"}}`, id)
	case "big":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"contents":[{"mimeType":"text/html","text":"%s"}]}}`, id, strings.Repeat("x", 3<<20))
	}
}

const session = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
`

const sessionOut = `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}
`

func TestGatewayProxy(t *testing.T) {
	g := newFakeGateway(t)
	var out strings.Builder
	if err := runProxy(g.url, strings.NewReader(session), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != sessionOut {
		t.Fatalf("out:\n%s\nwant:\n%s", out.String(), sessionOut)
	}
	var a GatewayAuth
	if err := load(gatewayFile(g.url), &a); err != nil || a.RefreshToken != g.rt || a.ClientID != "c1" {
		t.Fatalf("saved %+v, %v", a, err)
	}

	// The next run refreshes the saved sign-in instead of opening the browser.
	out.Reset()
	if err := runProxy(g.url, strings.NewReader(session), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != sessionOut || g.signIns != 1 {
		t.Fatalf("second run: %d sign-ins, out:\n%s", g.signIns, out.String())
	}
}

func TestGatewayProxyReportsFailures(t *testing.T) {
	g := newFakeGateway(t)
	var out strings.Builder
	in := `{"jsonrpc":"2.0","id":8,"method":"tools/list"}` + "\n"
	if err := runProxy(g.url, strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	// Without a session the gateway refuses it; the agent gets an error, not silence.
	if !strings.Contains(out.String(), `"id":8,"error"`) {
		t.Fatalf("out:\n%s", out.String())
	}
}

func TestGatewayProxyRenewsExpiredSession(t *testing.T) {
	g := newFakeGateway(t)
	g.expire = true
	var out strings.Builder
	in := session + `{"jsonrpc":"2.0","id":3,"method":"tools/list"}` + "\n"
	if err := runProxy(g.url, strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	// The two tools/list calls run concurrently; whichever comes second renews the session.
	for _, id := range []string{"2", "3"} {
		if !strings.Contains(out.String(), `{"jsonrpc":"2.0","id":`+id+`,"result":{"tools":[]}}`) {
			t.Fatalf("no reply to %s, out:\n%s", id, out.String())
		}
	}
	if g.sessions != 2 {
		t.Fatalf("%d sessions, out:\n%s", g.sessions, out.String())
	}
}

// notifyWriter signals once the gateway's notification was written.
type notifyWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	seen chan struct{}
}

func (w *notifyWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if bytes.Contains(b, []byte("list_changed")) {
		close(w.seen)
	}
	return w.buf.Write(b)
}

func TestGatewayProxyRelaysStream(t *testing.T) {
	g := newFakeGateway(t)
	g.stream = []string{`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`}
	out := &notifyWriter{seen: make(chan struct{})}
	in, feed := io.Pipe()
	go func() {
		_, _ = io.WriteString(feed, session)
		select {
		case <-out.seen:
		case <-time.After(5 * time.Second):
		}
		_ = feed.Close()
	}()
	if err := runProxy(g.url, in, out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.buf.String(), `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`) {
		t.Fatalf("out:\n%s", out.buf.String())
	}
}

func TestGatewayProxyReportsEarlyEnd(t *testing.T) {
	g := newFakeGateway(t)
	g.cut = true
	var out strings.Builder
	if err := runProxy(g.url, strings.NewReader(session), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"the gateway ended the reply early"}}`) {
		t.Fatalf("out:\n%s", out.String())
	}
}

func TestGatewayProxyChecksResource(t *testing.T) {
	g := newFakeGateway(t)
	g.resource = "https://elsewhere.example/mcp"
	var out strings.Builder
	if err := runProxy(g.url, strings.NewReader(session), &out); err != nil {
		t.Fatal(err)
	}
	if g.signIns != 0 || !strings.Contains(out.String(), "names another resource") {
		t.Fatalf("%d sign-ins, out:\n%s", g.signIns, out.String())
	}
}

// agent drives the proxy like an MCP client: one message per line each way.
type agent struct {
	t     *testing.T
	in    io.WriteCloser
	lines chan string
	done  chan error
}

func startAgent(t *testing.T, gw string) *agent {
	return launchAgent(t, gw).initialize()
}

func (a *agent) initialize() *agent {
	a.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	a.next()
	a.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return a
}

// launchAgent starts the proxy without initializing, as 2026-07-28 clients do.
func launchAgent(t *testing.T, gw string) *agent {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- runProxy(gw, inR, outW)
		_ = outW.Close()
	}()
	return newAgent(t, inW, outR, done)
}

// startProcess runs the proxy in its own process, as each agent on a machine does.
func startProcess(t *testing.T, gw string) *agent {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProxy$")
	cmd.Env = append(os.Environ(), "HUSH_TEST_PROXY="+gw)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return newAgent(t, in, out, done).initialize()
}

func TestHelperProxy(t *testing.T) {
	gw := os.Getenv("HUSH_TEST_PROXY")
	if gw == "" {
		t.Skip("runs as a proxy process for startProcess")
	}
	openBrowser = followRedirect
	if err := runProxy(gw, os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func newAgent(t *testing.T, in io.WriteCloser, out io.Reader, done chan error) *agent {
	a := &agent{t: t, in: in, lines: make(chan string, 1000), done: done}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(nil, 64<<20)
		for sc.Scan() {
			a.lines <- sc.Text()
		}
		close(a.lines)
	}()
	return a
}

func (a *agent) send(msg string) { _, _ = io.WriteString(a.in, msg+"\n") }

func (a *agent) next() string {
	a.t.Helper()
	select {
	case line := <-a.lines:
		return line
	case <-time.After(5 * time.Second):
		a.t.Fatal("no message from the proxy")
		return ""
	}
}

func (a *agent) stop() {
	_ = a.in.Close()
	if err := <-a.done; err != nil {
		a.t.Fatal(err)
	}
}

func TestGatewayProxyElicitation(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url)
	defer a.stop()
	a.send(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"consent"}}`)
	if got := a.next(); !strings.Contains(got, `"notifications/progress"`) {
		t.Fatalf("want progress first, got %s", got)
	}
	if got := a.next(); got != `{"jsonrpc":"2.0","id":7,"method":"elicitation/create","params":{"message":"Allow?"}}` {
		t.Fatalf("want the gateway's question, got %s", got)
	}
	a.send(`{"jsonrpc":"2.0","id":7,"result":{"action":"accept"}}`)
	if got := a.next(); got != `{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"{\"action\":\"accept\"}"}]}}` {
		t.Fatalf("want the call's result, got %s", got)
	}
}

func TestGatewayProxyManyCalls(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url)
	defer a.stop()
	const n = 50
	for i := range n {
		a.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"slow"}}`, 100+i))
	}
	seen := map[string]bool{}
	for range n {
		var m struct{ ID, Result json.RawMessage }
		_ = json.Unmarshal([]byte(a.next()), &m)
		if m.Result == nil {
			t.Fatalf("call %s failed", m.ID)
		}
		seen[string(m.ID)] = true
	}
	if len(seen) != n {
		t.Fatalf("%d distinct replies, want %d", len(seen), n)
	}
}

func TestGatewayProxyBigReply(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url)
	defer a.stop()
	a.send(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"big"}}`)
	if got := a.next(); len(got) < 3<<20 || !strings.HasPrefix(got, `{"jsonrpc":"2.0","id":9,"result"`) {
		t.Fatalf("got %d bytes: %.80s", len(got), got)
	}
}

// call sends a request and returns the proxy's reply to it.
func (a *agent) call(id int, method, params string) string {
	a.t.Helper()
	a.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, id, method, params))
	return a.next()
}

func TestGatewayProxyMethods(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url)
	defer a.stop()
	for i, c := range []struct{ method, params string }{
		{"ping", `{}`},
		{"resources/list", `{"cursor":"c2"}`},
		{"resources/read", `{"uri":"ui://hush/app.html"}`},
		{"resources/templates/list", `{}`},
		{"resources/subscribe", `{"uri":"file:///a b/ç.txt"}`},
		{"prompts/list", `{}`},
		{"prompts/get", `{"name":"summary","arguments":{"lang":"עברית","emoji":"🔐","esc":"a\"b\\c\n\u0000"}}`},
		{"completion/complete", `{"ref":{"type":"ref/prompt","name":"summary"},"argument":{"name":"lang","value":"en"}}`},
		{"logging/setLevel", `{"level":"debug"}`},
	} {
		want := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"echo":%s}}`, 10+i, c.params)
		if got := a.call(10+i, c.method, c.params); got != want {
			t.Errorf("%s:\n got %s\nwant %s", c.method, got, want)
		}
	}
}

func TestGatewayProxyServerRequests(t *testing.T) {
	g := newFakeGateway(t)
	stream := []string{ // what a gateway may send outside of replies
		`{"jsonrpc":"2.0","id":"p1","method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"hi"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"sampling/createMessage","params":{"messages":[],"maxTokens":10}}`,
		`{"jsonrpc":"2.0","id":"r1","method":"roots/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"ui://hush/app.html"}}`,
	}
	g.stream = stream
	a := startAgent(t, g.url)
	defer a.stop()
	for _, want := range stream {
		var m struct {
			ID     json.RawMessage
			Method string
		}
		got := a.next()
		if got != want {
			t.Fatalf("got %s\nwant %s", got, want)
		}
		if _ = json.Unmarshal([]byte(got), &m); m.ID != nil { // answer the gateway's requests
			a.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"for":%q}}`, m.ID, m.Method))
		}
	}
	for _, method := range []string{"ping", "sampling/createMessage", "roots/list"} {
		select {
		case answer := <-g.answers:
			if !strings.Contains(string(answer), method) {
				t.Fatalf("answer %s, want one for %s", answer, method)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no answer for %s reached the gateway", method)
		}
	}
}

func TestGatewayProxyReplies(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url)
	defer a.stop()
	for i, c := range []struct{ tool, want string }{
		{"odd", `{"jsonrpc":"2.0","id":%d,"result":{"content":[]}}`},
		{"iserror", `{"jsonrpc":"2.0","id":%d,"result":{"isError":true,"content":[{"type":"text","text":"denied"}]}}`},
		{"fail", `{"jsonrpc":"2.0","id":%d,"error":{"code":-32603,"message":"POST /mcp: 500 Internal Server Error upstream exploded"}}`},
	} {
		want := fmt.Sprintf(c.want, 20+i)
		if got := a.call(20+i, "tools/call", fmt.Sprintf(`{"name":%q}`, c.tool)); got != want {
			t.Errorf("%s:\n got %s\nwant %s", c.tool, got, want)
		}
	}
}

func TestGatewayProxyBigRequest(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url)
	defer a.stop()
	params := fmt.Sprintf(`{"uri":"file:///big","text":"%s"}`, strings.Repeat("y", 5<<20))
	if got := a.call(30, "resources/read", params); got != `{"jsonrpc":"2.0","id":30,"result":{"echo":`+params+`}}` {
		t.Fatalf("got %d bytes: %.80s", len(got), got)
	}
}

func TestGatewayProxyTokenExpires(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url)
	defer a.stop()
	g.mu.Lock()
	g.at = "" // the access token expired
	g.mu.Unlock()
	if got := a.call(40, "ping", `{}`); got != `{"jsonrpc":"2.0","id":40,"result":{"echo":{}}}` {
		t.Fatalf("got %s", got)
	}
	if g.signIns != 1 || g.tokens != 2 {
		t.Fatalf("%d sign-ins, %d tokens: want a silent refresh", g.signIns, g.tokens)
	}
}

// Two agents on one machine (say Claude Desktop and Claude Code) share the
// sign-in; its refresh token works once, so they must not both use it.
func TestGatewayProxyTwoProcesses(t *testing.T) {
	g := newFakeGateway(t)
	a1 := startProcess(t, g.url)
	defer a1.stop()
	a2 := startProcess(t, g.url) // refreshes, which invalidates a1's access token
	defer a2.stop()
	for round := range 3 {
		g.mu.Lock()
		g.at = "" // expire it for both
		g.mu.Unlock()
		for i, a := range []*agent{a1, a2} {
			a.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"ping"}`, 50+i))
		}
		for i, a := range []*agent{a1, a2} {
			if got := a.next(); got != fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"echo":null}}`, 50+i) {
				t.Fatalf("round %d, agent %d: %s", round, i+1, got)
			}
		}
	}
	if g.signIns != 1 {
		t.Fatalf("%d sign-ins, want 1", g.signIns)
	}
}

func TestGatewayProxyRefusesNonHTTPS(t *testing.T) {
	g := newFakeGateway(t)
	g.authorize = "file:///etc/passwd"
	opened := false
	openBrowser = func(string) error { opened = true; return nil }
	var out strings.Builder
	if err := runProxy(g.url, strings.NewReader(session), &out); err != nil {
		t.Fatal(err)
	}
	if opened || !strings.Contains(out.String(), "isn't https") {
		t.Fatalf("browser opened: %v, out:\n%s", opened, out.String())
	}
}

// The gateway's own request reusing the call's id is not the call's reply.
func TestGatewayProxyRequestIsNotReply(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url)
	defer a.stop()
	a.send(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"askthencut"}}`)
	a.next() // the gateway's question
	if got := a.next(); got != `{"jsonrpc":"2.0","id":8,"error":{"code":-32603,"message":"the gateway ended the reply early"}}` {
		t.Fatalf("got %s", got)
	}
}

func TestLogoutForgetsGateways(t *testing.T) {
	g := newFakeGateway(t)
	if err := runProxy(g.url, strings.NewReader(session), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := logout(); err != nil {
		t.Fatal(err)
	}
	var a GatewayAuth
	if err := load(gatewayFile(g.url), &a); err != nil || a.RefreshToken != "" {
		t.Fatalf("still signed in to the gateway: %+v, %v", a, err)
	}
}

// 2026-07-28 clients send no initialize; each request carries its version in _meta.
func TestGatewayProxyModernProtocol(t *testing.T) {
	g := newFakeGateway(t)
	a := launchAgent(t, g.url)
	defer a.stop()
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
	for i, params := range []string{
		`{` + meta + `}`,
		`{"name":"hush_list_apps",` + meta + `}`,
		`{"name":"ünïcode tool",` + meta + `}`,
		`{"uri":"ui://hush/app.html",` + meta + `}`,
	} {
		method := []string{"server/discover", "tools/call", "tools/call", "resources/read"}[i]
		want := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"result":{"echo":%s}}`, 60+i, params)
		if got := a.call(60+i, method, params); got != want {
			t.Errorf("%s:\n got %s\nwant %s", method, got, want)
		}
	}
	a.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":61}}`)
	if got := a.call(70, "tools/list", `{`+meta+`}`); !strings.Contains(got, `"result"`) {
		t.Fatalf("after a notification: %s", got)
	}
}
