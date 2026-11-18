package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/hushsecurity/hush-cli/internal/httpx"
)

// Gateways prompt in the chat (to approve a tool) only over 2026-07-28, which
// asks inside a call's result. For an older client that can prompt, the proxy
// makes the approval calls in that version and asks the client itself.
const modernVersion = "2026-07-28"

var errCancelled = errors.New("the client cancelled the call")

type clientInit struct {
	ProtocolVersion string                     `json:"protocolVersion"`
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
	ClientInfo      json.RawMessage            `json:"clientInfo"`
}

// bridges tells whether to make this call in the newer version. Only the
// approval tools are: the gateway won't relay an app's own questions in it.
func (p *proxy) bridges(call []byte) bool {
	var m struct {
		Params struct{ Name string } `json:"params"`
	}
	_ = json.Unmarshal(call, &m)
	if m.Params.Name != "hush_request_user_consent" && m.Params.Name != "hush_user_consent_methods" {
		return false
	}
	c := p.clientInit()
	_, prompts := c.Capabilities["elicitation"]
	return prompts && c.ProtocolVersion != "" && c.ProtocolVersion < modernVersion && p.modernGateway()
}

func (p *proxy) clientInit() clientInit {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.client
}

// modernGateway asks the gateway, until it answers, whether it takes the newer version.
func (p *proxy) modernGateway() bool {
	p.mu.Lock()
	known := p.modernGW
	p.mu.Unlock()
	if known != nil {
		return *known
	}
	var r struct {
		Result struct{ SupportedVersions []string } `json:"result"`
	}
	msg := upgrade([]byte(`{"jsonrpc":"2.0","id":"hush-discover","method":"server/discover","params":{}}`), p.clientInit())
	err := p.send(msg, false, func(m []byte) { _ = json.Unmarshal(m, &r) })
	var status *httpx.StatusError
	if err != nil && (!errors.As(err, &status) || status.Code >= 500 || status.Code == http.StatusTooManyRequests) {
		return false // ask again next time
	}
	ok := slices.Contains(r.Result.SupportedVersions, modernVersion)
	p.mu.Lock()
	p.modernGW = &ok
	p.mu.Unlock()
	return ok
}

// upgrade puts what each newer-version request carries into the call's _meta.
func upgrade(msg []byte, c clientInit) []byte {
	return withParams(msg, func(params map[string]json.RawMessage) {
		var meta map[string]json.RawMessage
		_ = json.Unmarshal(params["_meta"], &meta)
		if meta == nil { // absent or null
			meta = map[string]json.RawMessage{}
		}
		meta["io.modelcontextprotocol/protocolVersion"], _ = json.Marshal(modernVersion)
		meta["io.modelcontextprotocol/clientCapabilities"], _ = json.Marshal(c.Capabilities)
		if c.ClientInfo != nil {
			meta["io.modelcontextprotocol/clientInfo"] = c.ClientInfo
		}
		params["_meta"], _ = json.Marshal(meta)
	})
}

// withParams returns msg with its params changed by edit, or msg as is if it can't.
func withParams(msg []byte, edit func(map[string]json.RawMessage)) []byte {
	var m, params map[string]json.RawMessage
	if json.Unmarshal(msg, &m) != nil || json.Unmarshal(m["params"], &params) != nil || params == nil {
		return msg
	}
	edit(params)
	m["params"], _ = json.Marshal(params)
	out, err := json.Marshal(m)
	if err != nil {
		return msg
	}
	return out
}

type inputRequired struct {
	InputRequests map[string]struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params,omitempty"`
	} `json:"inputRequests"`
	RequestState json.RawMessage `json:"requestState"`
}

// inputRequiredOf returns what the gateway asks before it can answer, if anything.
func inputRequiredOf(reply []byte) *inputRequired {
	var m struct {
		Result *struct {
			ResultType string `json:"resultType"`
			inputRequired
		} `json:"result"`
	}
	if json.Unmarshal(reply, &m) != nil || m.Result == nil || m.Result.ResultType != "input_required" {
		return nil
	}
	return &m.Result.inputRequired
}

// track notes request id as in progress; its channel closes if the client cancels it.
func (p *proxy) track(id []byte) chan struct{} {
	stop := make(chan struct{})
	p.mu.Lock()
	p.pending[string(id)] = stop
	p.mu.Unlock()
	return stop
}

func (p *proxy) untrack(id []byte, stop chan struct{}) {
	p.mu.Lock()
	if p.pending[string(id)] == stop { // not a later request reusing the id
		delete(p.pending, string(id))
	}
	p.mu.Unlock()
}

func closed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// ask puts the gateway's questions to the client and returns the call again with the answers.
func (p *proxy) ask(call []byte, ir *inputRequired, stop chan struct{}) ([]byte, error) {
	answers := map[string]json.RawMessage{}
	for key, req := range ir.InputRequests {
		if closed(stop) {
			return nil, errCancelled
		}
		p.mu.Lock()
		p.asks++
		id := fmt.Appendf(nil, `"hush-input-%d"`, p.asks)
		answer := make(chan json.RawMessage, 1)
		p.asked[string(id)] = answer
		p.mu.Unlock()
		msg, _ := json.Marshal(struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params,omitempty"`
		}{"2.0", id, req.Method, req.Params})
		p.write(msg)
		var reply struct {
			Result json.RawMessage
			Error  *struct{ Message string }
		}
		var err error
		select {
		case m := <-answer:
			_ = json.Unmarshal(m, &reply)
		case <-stop:
			err = errCancelled
		case <-p.eof:
			err = errors.New("the client left before answering")
		}
		if err != nil { // close the client's open prompt
			p.mu.Lock()
			delete(p.asked, string(id))
			p.mu.Unlock()
			p.write(fmt.Appendf(nil, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":%s}}`, id))
			return nil, err
		}
		if reply.Error != nil {
			return nil, fmt.Errorf("the client couldn't answer %s: %s", req.Method, reply.Error.Message)
		}
		answers[key] = reply.Result
	}
	return withParams(call, func(params map[string]json.RawMessage) {
		params["inputResponses"], _ = json.Marshal(answers)
		params["requestState"] = ir.RequestState
		if ir.RequestState == nil || string(ir.RequestState) == "null" {
			delete(params, "requestState") // not the previous round's
		}
	}), nil
}

// answered hands a reply to ask; late ones are dropped.
func (p *proxy) answered(id, msg []byte) bool {
	p.mu.Lock()
	answer, ok := p.asked[string(id)]
	delete(p.asked, string(id))
	p.mu.Unlock()
	if ok {
		answer <- msg
	}
	return bytes.HasPrefix(id, []byte(`"hush-input-`))
}
