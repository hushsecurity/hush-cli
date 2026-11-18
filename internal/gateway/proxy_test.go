package gateway

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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hushsecurity/hush-cli/internal/config"
	"github.com/hushsecurity/hush-cli/internal/oauth"
)

// fakeGateway is an MCP endpoint that wants a bearer token, with its
// authorization server.
type fakeGateway struct {
	url string

	mu            sync.Mutex
	signIns       int
	tokens        int    // tokens issued
	at, rt        string // the valid access token, and the one refresh token that works
	sessions      int
	session       string               // the live one
	expire        bool                 // drop the session after the next tools/list
	stream        []string             // messages to send on the GET stream, once
	cut           bool                 // end tools/list streams before the reply
	resource      string               // metadata's resource, if not the gateway's
	authorize     string               // metadata's authorization endpoint, if not ours
	answers       chan json.RawMessage // the client's answers to our requests
	refuseModern  int                  // status for 2026-07-28 requests, like an older gateway; 0 takes them
	discoverFails int                  // 503s before server/discover answers
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
			_ = json.NewEncoder(w).Encode(oauth.Token{AccessToken: g.at, RefreshToken: g.rt})
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
	orig := oauth.OpenBrowser
	oauth.OpenBrowser = followRedirect
	t.Cleanup(func() { oauth.OpenBrowser = orig })
	if _, err := signInGateway(g.url, ""); err != nil { // as after hush_sign_in
		t.Fatal(err)
	}
	return g
}

// signOut forgets the saved sign-in, as on a new device.
func (g *fakeGateway) signOut(t *testing.T) {
	if err := config.Save(authFile(g.url), Auth{}); err != nil {
		t.Fatal(err)
	}
	g.signIns = 0
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
		switch {
		case g.refuseModern != 0:
			http.Error(w, "unsupported protocol version", g.refuseModern)
		case msg.Method == "server/discover" && g.discoverFails > 0:
			g.discoverFails--
			http.Error(w, "busy", http.StatusServiceUnavailable)
		default:
			g.serveModern(w, r, v, msg.ID, msg.Method, msg.Params)
		}
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
func (g *fakeGateway) serveModern(w http.ResponseWriter, r *http.Request, version string, id json.RawMessage, method string, params json.RawMessage) {
	var p struct {
		Name, URI      string
		Meta           map[string]any  `json:"_meta"`
		InputResponses json.RawMessage `json:"inputResponses"`
		RequestState   string          `json:"requestState"`
		Arguments      struct {
			Rounds  int      // questions asked before answering, 1 if unset
			Ask     []string // the questions in each round, "ok" if unset
			Slow    bool     // asks after a while
			Cut     bool     // ends the stream with an error after asking
			NoState bool     // asks without a requestState
			Later   bool     // asks again, without a requestState, after the first answer
		}
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
	case method == "server/discover":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"supportedVersions":["2025-11-25","2026-07-28"]}}`, id)
	case p.Name == "hush_request_user_consent": // asks in the result, as the gateway prompts
		if p.Meta["io.modelcontextprotocol/clientCapabilities"] == nil {
			http.Error(w, "no client capabilities", http.StatusBadRequest)
			return
		}
		round, _ := strconv.Atoi(strings.TrimPrefix(p.RequestState, "st"))
		if p.Arguments.NoState && p.InputResponses != nil {
			round = 1
		}
		if p.Arguments.Later && p.RequestState == "st1" {
			p.Arguments.NoState, round = true, 0
		} else if p.Arguments.Later && p.InputResponses != nil {
			round = 1
		}
		w.Header().Set("Content-Type", "application/json")
		if round >= max(p.Arguments.Rounds, 1) {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","content":[{"type":"text","text":%q}]}}`, id, p.RequestState+" "+string(p.InputResponses))
			return
		}
		if p.Arguments.Slow {
			g.mu.Unlock()
			time.Sleep(200 * time.Millisecond)
			g.mu.Lock()
		}
		requests := map[string]any{}
		if p.Arguments.Ask == nil {
			p.Arguments.Ask = []string{"ok"}
		}
		for _, key := range p.Arguments.Ask {
			requests[key] = map[string]any{"method": "elicitation/create", "params": map[string]string{"message": key + "?"}}
		}
		result := map[string]any{"resultType": "input_required", "inputRequests": requests, "requestState": fmt.Sprintf("st%d", round+1)}
		if p.Arguments.NoState {
			delete(result, "requestState")
		}
		out, _ := json.Marshal(result)
		if p.Arguments.Cut {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}\n\n", id, out)
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, id, out)
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
	case "consent", "hush_request_user_consent":
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
	var a Auth
	if err := config.Load(authFile(g.url), &a); err != nil || a.RefreshToken != g.rt || a.ClientID != "c1" {
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

const toolCall = `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"slow"}}` + "\n"

func TestGatewayProxyChecksResource(t *testing.T) {
	g := newFakeGateway(t)
	g.signOut(t)
	g.resource = "https://elsewhere.example/mcp"
	var out strings.Builder
	if err := runProxy(g.url, strings.NewReader(session+toolCall), &out); err != nil {
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
	oauth.OpenBrowser = followRedirect
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

// oldAgent is a client before 2026-07-28 that can prompt.
func oldAgent(t *testing.T, gw string) *agent {
	a := launchAgent(t, gw)
	a.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"elicitation":{}},"clientInfo":{"name":"old"}}}`)
	a.next()
	a.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return a
}

const consentCall = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"hush_request_user_consent","arguments":%s}}`

// The gateway's questions about an approval reach an older client as requests of its own.
func TestGatewayProxyBridgesInputRequests(t *testing.T) {
	g := newFakeGateway(t)
	a := oldAgent(t, g.url)
	defer a.stop()
	a.send(fmt.Sprintf(consentCall, `{}`))
	if got := a.next(); got != `{"jsonrpc":"2.0","id":"hush-input-1","method":"elicitation/create","params":{"message":"ok?"}}` {
		t.Fatalf("want the gateway's question, got %s", got)
	}
	a.send(`{"jsonrpc":"2.0","id":"hush-input-1","result":{"action":"accept"}}`)
	if got := a.next(); got != `{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","content":[{"type":"text","text":"st1 {\"ok\":{\"action\":\"accept\"}}"}]}}` {
		t.Fatalf("want the call's result, got %s", got)
	}
	// Other calls, apps' included, stay in the client's version and session.
	if got := a.call(8, "tools/list", `{}`); got != `{"jsonrpc":"2.0","id":8,"result":{"tools":[]}}` {
		t.Fatalf("got %s", got)
	}
	if got := a.call(9, "tools/call", `{"name":"iserror"}`); !strings.HasPrefix(got, `{"jsonrpc":"2.0","id":9,"result":{"isError":true`) {
		t.Fatalf("want the app's own reply, got %s", got)
	}
}

func TestUpgrade(t *testing.T) {
	c := clientInit{Capabilities: map[string]json.RawMessage{"elicitation": json.RawMessage(`{}`)}}
	for _, meta := range []string{`null`, `{"progressToken":9007199254740993}`} {
		got := string(upgrade([]byte(`{"jsonrpc":"2.0","id":1,"params":{"name":"x","_meta":`+meta+`}}`), c))
		if !strings.Contains(got, `"io.modelcontextprotocol/protocolVersion":"2026-07-28"`) ||
			meta != "null" && !strings.Contains(got, `"progressToken":9007199254740993`) {
			t.Errorf("%s: got %s", meta, got)
		}
	}
}

// A question without a requestState is answered without one.
func TestGatewayProxyBridgesWithoutState(t *testing.T) {
	g := newFakeGateway(t)
	a := oldAgent(t, g.url)
	defer a.stop()
	a.send(fmt.Sprintf(consentCall, `{"noState":true}`))
	a.next()
	a.send(`{"jsonrpc":"2.0","id":"hush-input-1","result":{"action":"decline"}}`)
	if got := a.next(); !strings.Contains(got, `" {\"ok\":{\"action\":\"decline\"}}"`) {
		t.Fatalf("got %s", got)
	}
}

// A later question without a requestState isn't answered with the earlier round's.
func TestGatewayProxyBridgesLaterWithoutState(t *testing.T) {
	g := newFakeGateway(t)
	a := oldAgent(t, g.url)
	defer a.stop()
	a.send(fmt.Sprintf(consentCall, `{"later":true}`))
	for i := range 2 {
		a.next()
		a.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":"hush-input-%d","result":{"action":"accept"}}`, i+1))
	}
	if got := a.next(); !strings.Contains(got, `"text":" {\"ok\":{\"action\":\"accept\"}}"`) {
		t.Fatalf("got %s", got)
	}
}

// Several questions at once, over several rounds, each get answered.
func TestGatewayProxyBridgesRounds(t *testing.T) {
	g := newFakeGateway(t)
	a := oldAgent(t, g.url)
	defer a.stop()
	a.send(fmt.Sprintf(consentCall, `{"rounds":2,"ask":["a","b"]}`))
	for range 4 {
		var q struct{ ID json.RawMessage }
		_ = json.Unmarshal([]byte(a.next()), &q)
		a.send(`{"jsonrpc":"2.0","id":` + string(q.ID) + `,"result":{"action":"accept"}}`)
	}
	if got := a.next(); !strings.Contains(got, `st2 {\"a\":{\"action\":\"accept\"},\"b\":{\"action\":\"accept\"}}`) {
		t.Fatalf("want both answers of the last round, got %s", got)
	}
}

func TestGatewayProxyBridgeFailures(t *testing.T) {
	g := newFakeGateway(t)
	a := oldAgent(t, g.url)
	defer a.stop()

	// The client can't answer.
	a.send(fmt.Sprintf(consentCall, `{}`))
	a.next()
	a.send(`{"jsonrpc":"2.0","id":"hush-input-1","error":{"code":-32601,"message":"no"}}`)
	if got := a.next(); got != `{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"the client couldn't answer elicitation/create: no"}}` {
		t.Fatalf("got %s", got)
	}

	// The gateway never stops asking.
	a.send(fmt.Sprintf(consentCall, `{"rounds":99}`))
	for i := range 10 {
		a.next()
		a.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":"hush-input-%d","result":{"action":"accept"}}`, i+2))
	}
	if got := a.next(); got != `{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"the gateway kept asking for more input"}}` {
		t.Fatalf("got %s", got)
	}

	// A cancelled call gets no reply, and its late answer goes nowhere.
	a.send(fmt.Sprintf(consentCall, `{}`))
	a.next()
	a.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`)
	if got := a.next(); got != `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"hush-input-12"}}` {
		t.Fatalf("want the open question closed, got %s", got)
	}
	a.send(`{"jsonrpc":"2.0","id":"hush-input-12","result":{"action":"accept"}}`)
	if got := a.call(8, "tools/list", `{}`); got != `{"jsonrpc":"2.0","id":8,"result":{"tools":[]}}` {
		t.Fatalf("want only the next reply, got %s", got)
	}

	// Cancelled while the gateway works on it: no question, no reply.
	a.send(fmt.Sprintf(consentCall, `{"slow":true}`))
	a.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`)
	time.Sleep(400 * time.Millisecond)
	if got := a.call(8, "tools/list", `{}`); got != `{"jsonrpc":"2.0","id":8,"result":{"tools":[]}}` {
		t.Fatalf("want only the next reply, got %s", got)
	}

	// The stream breaks after the gateway asked: the question still goes out.
	a.send(fmt.Sprintf(consentCall, `{"cut":true}`))
	if got := a.next(); got != `{"jsonrpc":"2.0","id":"hush-input-13","method":"elicitation/create","params":{"message":"ok?"}}` {
		t.Fatalf("got %s", got)
	}
	a.send(`{"jsonrpc":"2.0","id":"hush-input-13","result":{"action":"accept"}}`)
	if got := a.next(); !strings.Contains(got, `st1 {\"ok\":{\"action\":\"accept\"}}`) {
		t.Fatalf("got %s", got)
	}

	// The client leaves with a question open: stop still sees the proxy end.
	a.send(fmt.Sprintf(consentCall, `{}`))
	a.next()
}

// Clients that can't prompt, and gateways before 2026-07-28, keep the client's version.
func TestGatewayProxyBridgesOnlyWhenBothCan(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url) // can't prompt
	a.send(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"hush_request_user_consent"}}`)
	a.next() // progress
	if got := a.next(); got != `{"jsonrpc":"2.0","id":7,"method":"elicitation/create","params":{"message":"Allow?"}}` {
		t.Fatalf("want the gateway's own question, got %s", got)
	}
	a.send(`{"jsonrpc":"2.0","id":7,"result":{"action":"accept"}}`)
	a.next()
	a.stop()

	g = newFakeGateway(t)
	g.refuseModern = http.StatusNotFound
	a = oldAgent(t, g.url)
	defer a.stop()
	a.send(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"hush_request_user_consent"}}`)
	a.next() // progress
	if got := a.next(); got != `{"jsonrpc":"2.0","id":7,"method":"elicitation/create","params":{"message":"Allow?"}}` {
		t.Fatalf("want the gateway's own question, got %s", got)
	}
	a.send(`{"jsonrpc":"2.0","id":7,"result":{"action":"accept"}}`)
	a.next()
	if g.sessions != 1 { // the 404 to discover isn't the client's session expiring
		t.Fatalf("%d sessions", g.sessions)
	}
}

// A gateway that fails to say which versions it takes is asked again.
func TestGatewayProxyRediscovers(t *testing.T) {
	g := newFakeGateway(t)
	g.discoverFails = 1
	a := oldAgent(t, g.url)
	defer a.stop()
	a.send(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"hush_user_consent_methods"}}`)
	if got := a.next(); strings.Contains(got, "2026-07-28") {
		t.Fatalf("want the call in the client's version while the gateway's are unknown, got %s", got)
	}
	got := a.call(8, "tools/call", `{"name":"hush_user_consent_methods"}`)
	if !strings.Contains(got, `"io.modelcontextprotocol/protocolVersion":"2026-07-28"`) {
		t.Fatalf("want the call in the newer version, got %s", got)
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
	if g.signIns != 1 || g.tokens != 3 { // the sign-in, the proxy's start, the expiry
		t.Fatalf("%d sign-ins, %d tokens: want a silent refresh", g.signIns, g.tokens)
	}
}

// Signed out, the proxy opens no browser by itself: it lists the gateway's
// tools, and the first call signs in.
func TestGatewayProxySignsInOnDemand(t *testing.T) {
	g := newFakeGateway(t)
	g.signOut(t)
	a := launchAgent(t, g.url)
	defer a.stop()
	a.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	if got := a.next(); !strings.Contains(got, `"protocolVersion":"2025-11-25"`) || !strings.Contains(got, "hush_list_apps") {
		t.Fatalf("initialize: %s", got)
	}
	a.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if got := a.call(2, "tools/list", `{}`); !strings.Contains(got, `"name":"hush_list_apps"`) || g.signIns != 0 {
		t.Fatalf("%d sign-ins, tools/list: %s", g.signIns, got)
	}
	a.send(toolCall)
	for _, list := range []string{"tools", "prompts", "resources"} {
		if got := a.next(); got != `{"jsonrpc":"2.0","method":"notifications/`+list+`/list_changed"}` {
			t.Fatalf("want %s list_changed: %s", list, got)
		}
	}
	if got := a.next(); got != `{"jsonrpc":"2.0","id":3,"result":{"content":[]}}` || g.signIns != 1 {
		t.Fatalf("%d sign-ins, call: %s", g.signIns, got)
	}
	if got := a.call(4, "tools/list", `{}`); got != `{"jsonrpc":"2.0","id":4,"result":{"tools":[]}}` {
		t.Fatalf("tools/list: %s", got)
	}
}

// Calls made while signing in wait for that one sign-in.
func TestGatewayProxyCallsShareSignIn(t *testing.T) {
	g := newFakeGateway(t)
	g.signOut(t)
	a := startAgent(t, g.url)
	defer a.stop()
	a.send(strings.TrimSpace(toolCall))
	a.send(strings.Replace(strings.TrimSpace(toolCall), `"id":3`, `"id":4`, 1))
	results := 0
	for range 5 { // 3 list_changed, 2 results
		if strings.Contains(a.next(), `"result":{"content":[]}`) {
			results++
		}
	}
	if results != 2 || g.signIns != 1 {
		t.Fatalf("%d results, %d sign-ins", results, g.signIns)
	}
}

// Calls that waited on a failed sign-in don't each open a browser again.
func TestGatewayProxyCallsShareFailedSignIn(t *testing.T) {
	g := newFakeGateway(t)
	g.signOut(t)
	opened := 0
	oauth.OpenBrowser = func(u string) error {
		opened++
		go func() {
			time.Sleep(50 * time.Millisecond) // the second call waits meanwhile
			q, _ := url.Parse(u)
			back := q.Query().Get("redirect_uri") + "?" + url.Values{"error": {"access_denied"}, "state": {q.Query().Get("state")}}.Encode()
			if resp, err := http.Get(back); err == nil {
				_ = resp.Body.Close()
			}
		}()
		return nil
	}
	a := startAgent(t, g.url)
	defer a.stop()
	a.send(strings.TrimSpace(toolCall))
	a.send(strings.Replace(strings.TrimSpace(toolCall), `"id":3`, `"id":4`, 1))
	for range 2 {
		if got := a.next(); !strings.Contains(got, "access_denied") {
			t.Fatalf("call: %s", got)
		}
	}
	if opened != 1 {
		t.Fatalf("browser opened %d times", opened)
	}
}

// A call cancelled while the user signs in isn't sent after.
func TestGatewayProxyDropsCancelledCall(t *testing.T) {
	g := newFakeGateway(t)
	g.signOut(t)
	oauth.OpenBrowser = func(u string) error {
		go func() {
			time.Sleep(50 * time.Millisecond) // the client cancels meanwhile
			_ = followRedirect(u)
		}()
		return nil
	}
	a := startAgent(t, g.url)
	defer a.stop()
	a.send(strings.TrimSpace(toolCall))
	a.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}`)
	for range 3 {
		a.next() // list_changed
	}
	if got := a.call(4, "tools/list", `{}`); got != `{"jsonrpc":"2.0","id":4,"result":{"tools":[]}}` {
		t.Fatalf("want no reply to the cancelled call: %s", got)
	}
}

// A sign-in the gateway stops honoring is renewed in the browser by the next call.
func TestGatewayProxySignInExpires(t *testing.T) {
	g := newFakeGateway(t)
	a := startAgent(t, g.url)
	defer a.stop()
	g.mu.Lock()
	g.at, g.rt = "", "" // e.g. the user was signed out of the gateway
	g.mu.Unlock()
	a.send(strings.Replace(toolCall, `"id":3`, `"id":5`, 1))
	for range 6 { // signed out, then in
		if got := a.next(); !strings.Contains(got, "/list_changed") {
			t.Fatalf("want list_changed: %s", got)
		}
	}
	if got := a.next(); got != `{"jsonrpc":"2.0","id":5,"result":{"content":[]}}` || g.signIns != 2 {
		t.Fatalf("%d sign-ins, call: %s", g.signIns, got)
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
	g.signOut(t)
	g.authorize = "file:///etc/passwd"
	opened := false
	oauth.OpenBrowser = func(string) error { opened = true; return nil }
	var out strings.Builder
	if err := runProxy(g.url, strings.NewReader(session+toolCall), &out); err != nil {
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

func TestForgetAll(t *testing.T) {
	g := newFakeGateway(t)
	if err := runProxy(g.url, strings.NewReader(session), io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := ForgetAll(); err != nil {
		t.Fatal(err)
	}
	var a Auth
	if err := config.Load(authFile(g.url), &a); err != nil || a.RefreshToken != "" {
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
		if i == 0 {
			want = `{"jsonrpc":"2.0","id":60,"result":{"supportedVersions":["2025-11-25","2026-07-28"]}}`
		}
		if got := a.call(60+i, method, params); got != want {
			t.Errorf("%s:\n got %s\nwant %s", method, got, want)
		}
	}
	a.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":61}}`)
	if got := a.call(70, "tools/list", `{`+meta+`}`); !strings.Contains(got, `"result"`) {
		t.Fatalf("after a notification: %s", got)
	}
}

func TestWithText(t *testing.T) {
	got := string(withText([]byte(`{"jsonrpc":"2.0","id":12345678901234567890,"result":{"content":[{"type":"text","text":"a"}],"isError":false}}`), "b"))
	if got != `{"jsonrpc":"2.0","id":12345678901234567890,"result":{"content":[{"text":"a","type":"text"},{"text":"b","type":"text"}],"isError":false}}` {
		t.Fatalf("got %s", got)
	}
	for _, msg := range []string{`{"jsonrpc":"2.0","id":1,"error":{"code":1}}`, `{"jsonrpc":"2.0","id":1,"result":{}}`} {
		if got := string(withText([]byte(msg), "b")); got != msg {
			t.Fatalf("changed %s: %s", msg, got)
		}
	}
}
