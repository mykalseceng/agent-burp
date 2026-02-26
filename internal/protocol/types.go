package protocol

import "encoding/json"

type Envelope struct {
	Success bool      `json:"success"`
	Data    any       `json:"data,omitempty"`
	Error   *ErrBody  `json:"error,omitempty"`
	Meta    *MetaBody `json:"meta,omitempty"`
}

type ErrBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type MetaBody struct {
	Command    string `json:"command"`
	DurationMS int64  `json:"duration_ms"`
	RequestID  string `json:"request_id,omitempty"`
}

type IPCRequest struct {
	Action    string         `json:"action"`
	Method    string         `json:"method,omitempty"`
	Params    map[string]any `json:"params,omitempty"`
	TimeoutMS int            `json:"timeout_ms,omitempty"`
}

type IPCResponse struct {
	OK       bool           `json:"ok"`
	Result   any            `json:"result,omitempty"`
	Error    *IPCError      `json:"error,omitempty"`
	BurpConn bool           `json:"burp_conn,omitempty"`
	Meta     map[string]any `json:"meta,omitempty"`
}

type IPCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type JSONRPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      string         `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}
