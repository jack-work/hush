package agent

import "encoding/json"

// Request is the JSON envelope sent by clients over the unix socket.
type Request struct {
	Op     string            `json:"op"`
	Values map[string]string `json:"values,omitempty"` // used by "decrypt"
}

// Response is the JSON envelope returned by the agent.
type Response struct {
	OK           bool              `json:"ok"`
	Error        string            `json:"error,omitempty"`
	Values       map[string]string `json:"values,omitempty"`        // used by "decrypt"
	TTLRemaining string            `json:"ttl_remaining,omitempty"` // used by "status"
}

func errResponse(msg string) []byte {
	b, _ := json.Marshal(Response{OK: false, Error: msg})
	return b
}

func okResponse(r Response) []byte {
	r.OK = true
	b, _ := json.Marshal(r)
	return b
}
