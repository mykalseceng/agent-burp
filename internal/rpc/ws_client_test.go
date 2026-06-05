package rpc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-burp/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestWSClientAllowsConcurrentCalls(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer conn.Close()

		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}

			var req protocol.JSONRPCRequest
			if err := json.Unmarshal(msg, &req); err != nil {
				t.Errorf("decode request: %v", err)
				return
			}

			result, err := json.Marshal(map[string]any{"method": req.Method})
			if err != nil {
				t.Errorf("encode result: %v", err)
				return
			}

			resp, err := json.Marshal(protocol.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  result,
			})
			if err != nil {
				t.Errorf("encode response: %v", err)
				return
			}

			if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	client := NewWSClient("ws"+strings.TrimPrefix(server.URL, "http"), "", time.Second)

	var wg sync.WaitGroup
	errs := make(chan error, 25)
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Call("get_proxy_history", map[string]any{"search": "/api/permissions"}, time.Second)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent call failed: %v", err)
		}
	}
}
