package cmd

import (
	"encoding/json"
	"net"
	"time"

	"github.com/jack-work/hush/agent"
)

// rpc sends a request to the agent over the unix socket and returns the response.
func rpc(sockPath string, req agent.Request) (*agent.Response, error) {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp agent.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
