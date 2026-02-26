package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"agent-burp/internal/protocol"
	"github.com/gorilla/websocket"
)

type pendingCall struct {
	ch chan protocol.JSONRPCResponse
}

type WSClient struct {
	url     string
	token   string
	timeout time.Duration

	mu      sync.Mutex
	conn    *websocket.Conn
	pending map[string]*pendingCall
	reqID   uint64
}

func NewWSClient(url, token string, timeout time.Duration) *WSClient {
	return &WSClient{
		url:     url,
		token:   token,
		timeout: timeout,
		pending: make(map[string]*pendingCall),
	}
}

func (c *WSClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil
	}

	header := http.Header{}
	if c.token != "" {
		header.Set("Authorization", "Bearer "+c.token)
	}

	dialer := websocket.Dialer{HandshakeTimeout: c.timeout}
	conn, _, err := dialer.Dial(c.url, header)
	if err != nil {
		return err
	}

	c.conn = conn
	go c.readLoop(conn)
	return nil
}

func (c *WSClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

func (c *WSClient) Close() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	c.pending = make(map[string]*pendingCall)
	c.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}

	for _, p := range pending {
		close(p.ch)
	}
}

func (c *WSClient) Call(method string, params map[string]any, timeout time.Duration) (any, error) {
	if err := c.Connect(); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = c.timeout
	}

	id := fmt.Sprintf("%d", atomic.AddUint64(&c.reqID, 1))
	req := protocol.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	p := &pendingCall{ch: make(chan protocol.JSONRPCResponse, 1)}

	c.mu.Lock()
	conn := c.conn
	if conn == nil {
		c.mu.Unlock()
		return nil, errors.New("websocket disconnected")
	}
	c.pending[id] = p
	c.mu.Unlock()

	b, _ := json.Marshal(req)
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}

	select {
	case resp, ok := <-p.ch:
		if !ok {
			return nil, errors.New("connection closed")
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("rpc %d: %s", resp.Error.Code, resp.Error.Message)
		}
		var result any
		if len(resp.Result) == 0 {
			return map[string]any{}, nil
		}
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			return nil, err
		}
		return result, nil
	case <-time.After(timeout):
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, errors.New("request timed out")
	}
}

func (c *WSClient) readLoop(conn *websocket.Conn) {
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			c.Close()
			return
		}

		var resp protocol.JSONRPCResponse
		if err := json.Unmarshal(msg, &resp); err != nil {
			continue
		}

		c.mu.Lock()
		p := c.pending[resp.ID]
		delete(c.pending, resp.ID)
		c.mu.Unlock()

		if p != nil {
			p.ch <- resp
		}
	}
}
