package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"agent-burp/internal/config"
	"agent-burp/internal/protocol"
	"agent-burp/internal/rpc"
)

type Server struct {
	cfg       config.Config
	logger    *log.Logger
	wsClient  *rpc.WSClient
	shutdown  chan struct{}
	closeOnce sync.Once
}

func NewServer(cfg config.Config, logger *log.Logger) *Server {
	return &Server{
		cfg:      cfg,
		logger:   logger,
		shutdown: make(chan struct{}),
	}
}

func (s *Server) Run(ctx context.Context) error {
	_ = os.Remove(s.cfg.DaemonSocketPath)

	ln, err := net.Listen("unix", s.cfg.DaemonSocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(s.cfg.DaemonSocketPath)
	}()

	if err := os.Chmod(s.cfg.DaemonSocketPath, 0o600); err != nil {
		return err
	}

	s.logger.Printf("daemon listening on %s", s.cfg.DaemonSocketPath)

	go func() {
		select {
		case <-ctx.Done():
			s.initiateShutdown()
		case <-s.shutdown:
		}
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				s.cleanup()
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				s.cleanup()
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var req protocol.IPCRequest
	if err := dec.Decode(&req); err != nil {
		_ = enc.Encode(protocol.IPCResponse{OK: false, Error: &protocol.IPCError{Code: "INVALID_IPC", Message: err.Error()}})
		return
	}

	resp := s.handle(req)
	_ = enc.Encode(resp)
}

func (s *Server) handle(req protocol.IPCRequest) protocol.IPCResponse {
	switch req.Action {
	case "ping":
		return protocol.IPCResponse{OK: true, Result: map[string]any{"status": "ok"}, BurpConn: s.isBurpConnected()}
	case "status":
		return protocol.IPCResponse{OK: true, Result: map[string]any{"daemon": "running", "socket": s.cfg.DaemonSocketPath}, BurpConn: s.isBurpConnected()}
	case "open":
		if err := s.ensureWS(); err != nil {
			return protocol.IPCResponse{OK: false, Error: &protocol.IPCError{Code: "BURP_CONNECT_ERROR", Message: err.Error()}, BurpConn: false}
		}
		return protocol.IPCResponse{OK: true, Result: map[string]any{"connected": true}, BurpConn: true}
	case "close":
		if s.wsClient != nil {
			s.wsClient.Close()
		}
		return protocol.IPCResponse{OK: true, Result: map[string]any{"connected": false}, BurpConn: false}
	case "call":
		if req.Method == "" {
			return protocol.IPCResponse{OK: false, Error: &protocol.IPCError{Code: "INVALID_PARAMS", Message: "method required"}}
		}
		if err := s.ensureWS(); err != nil {
			return protocol.IPCResponse{OK: false, Error: &protocol.IPCError{Code: "BURP_CONNECT_ERROR", Message: err.Error()}, BurpConn: false}
		}
		timeout := time.Duration(req.TimeoutMS) * time.Millisecond
		result, err := s.wsClient.Call(req.Method, req.Params, timeout)
		if err != nil {
			return protocol.IPCResponse{OK: false, Error: &protocol.IPCError{Code: "BURP_RPC_ERROR", Message: err.Error()}, BurpConn: s.isBurpConnected()}
		}
		return protocol.IPCResponse{OK: true, Result: result, BurpConn: s.isBurpConnected()}
	case "shutdown":
		s.initiateShutdown()
		return protocol.IPCResponse{OK: true, Result: map[string]any{"shutdown": true}, BurpConn: s.isBurpConnected()}
	default:
		return protocol.IPCResponse{OK: false, Error: &protocol.IPCError{Code: "UNKNOWN_ACTION", Message: fmt.Sprintf("unknown action: %s", req.Action)}}
	}
}

func (s *Server) ensureWS() error {
	if s.wsClient == nil {
		s.wsClient = rpc.NewWSClient(s.cfg.BurpWSURL, s.cfg.BurpAuthToken, time.Duration(s.cfg.RequestTimeoutMS)*time.Millisecond)
	}
	return s.wsClient.Connect()
}

func (s *Server) isBurpConnected() bool {
	if s.wsClient == nil {
		return false
	}
	return s.wsClient.IsConnected()
}

func (s *Server) initiateShutdown() {
	s.closeOnce.Do(func() { close(s.shutdown) })
}

func (s *Server) cleanup() {
	if s.wsClient != nil {
		s.wsClient.Close()
	}
}
