package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"agent-burp/internal/protocol"
)

type Client struct {
	socketPath string
	timeout    time.Duration
}

func NewClient(socketPath string, timeout time.Duration) *Client {
	return &Client{socketPath: socketPath, timeout: timeout}
}

func (c *Client) Send(ctx context.Context, req protocol.IPCRequest) (protocol.IPCResponse, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return protocol.IPCResponse{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if err := enc.Encode(req); err != nil {
		return protocol.IPCResponse{}, err
	}

	var resp protocol.IPCResponse
	if err := dec.Decode(&resp); err != nil {
		return protocol.IPCResponse{}, err
	}
	if !resp.OK && resp.Error == nil {
		return protocol.IPCResponse{}, errors.New("daemon returned non-ok without error")
	}
	return resp, nil
}
