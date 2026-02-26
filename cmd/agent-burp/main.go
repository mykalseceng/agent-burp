package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agent-burp/internal/config"
	"agent-burp/internal/daemon"
	"agent-burp/internal/protocol"
)

const (
	exitOK         = 0
	exitBadArgs    = 2
	exitConnect    = 3
	exitRPC        = 4
	exitTimeout    = 5
	defaultReqName = "agent-burp"
)

type appError struct {
	ExitCode int
	Code     string
	Message  string
	Details  any
}

func (e *appError) Error() string { return e.Message }

type headerFlags []string

func (h *headerFlags) String() string { return strings.Join(*h, ",") }
func (h *headerFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}

type kvFlags []string

func (k *kvFlags) String() string { return strings.Join(*k, ",") }
func (k *kvFlags) Set(v string) error {
	*k = append(*k, v)
	return nil
}

func main() {
	start := time.Now()
	err := run(start)
	if err == nil {
		os.Exit(exitOK)
	}

	var ae *appError
	if errors.As(err, &ae) {
		printErrorEnvelope(ae, start)
		os.Exit(ae.ExitCode)
	}

	printErrorEnvelope(&appError{ExitCode: exitBadArgs, Code: "INTERNAL", Message: err.Error()}, start)
	os.Exit(exitBadArgs)
}

func run(start time.Time) error {
	global := flag.NewFlagSet("agent-burp", flag.ContinueOnError)
	global.SetOutput(io.Discard)

	var cfgPath, wsURL, authToken, output string
	var timeoutMS int
	var jsonOutput, debug bool

	global.StringVar(&cfgPath, "config", "", "config file path")
	global.StringVar(&wsURL, "ws-url", "", "Burp websocket URL")
	global.StringVar(&authToken, "auth-token", "", "Burp auth token")
	global.IntVar(&timeoutMS, "timeout", 0, "request timeout ms")
	global.StringVar(&output, "output", "", "output mode text|json")
	global.BoolVar(&jsonOutput, "json", false, "JSON output")
	global.BoolVar(&debug, "debug", false, "debug logging")

	globalArgs, remainingArgs := extractGlobalArgs(os.Args[1:])
	if err := global.Parse(globalArgs); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}

	args := remainingArgs
	if len(args) == 0 {
		printUsage()
		return nil
	}

	if jsonOutput {
		output = "json"
	}

	cfg, err := config.Load(config.Overrides{
		ConfigPath:       cfgPath,
		BurpWSURL:        wsURL,
		BurpAuthToken:    authToken,
		RequestTimeoutMS: timeoutMS,
		Output:           output,
		Debug:            debug,
	})
	if err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "CONFIG_ERROR", Message: err.Error()}
	}
	if err := config.EnsureRuntimeDirs(cfg); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "CONFIG_ERROR", Message: err.Error()}
	}

	jsonMode := cfg.Output == "json"
	cmd := args[0]
	sub := args[1:]

	switch cmd {
	case "doctor":
		return runDoctor(cfg, jsonMode, start)
	case "capabilities":
		return runCapabilities(cfg, jsonMode, start)
	case "open":
		return runOpen(cfg, jsonMode, start)
	case "close":
		return runClose(cfg, jsonMode, start)
	case "request":
		return runRequest(cfg, sub, jsonMode, start)
	case "http1":
		return runHTTP1(cfg, sub, jsonMode, start)
	case "http2":
		return runHTTP2(cfg, sub, jsonMode, start)
	case "editor":
		return runEditor(cfg, sub, jsonMode, start)
	case "runtime":
		return runRuntime(cfg, sub, jsonMode, start)
	case "transform":
		return runTransform(cfg, sub, jsonMode, start)
	case "ws-history":
		return runWSHistory(cfg, sub, jsonMode, start)
	case "job":
		return runJob(cfg, sub, jsonMode, start)
	case "crawl":
		return runCrawl(cfg, sub, jsonMode, start)
	case "export":
		return runExport(cfg, sub, jsonMode, start)
	case "replay":
		return runReplay(cfg, sub, jsonMode, start)
	case "events":
		return runEvents(cfg, sub, jsonMode, start)
	case "history":
		return runHistory(cfg, sub, jsonMode, start)
	case "sitemap":
		return runSitemap(cfg, sub, jsonMode, start)
	case "scope":
		return runScope(cfg, sub, jsonMode, start)
	case "repeater":
		return runRepeater(cfg, sub, jsonMode, start)
	case "intruder":
		return runIntruder(cfg, sub, jsonMode, start)
	case "scan":
		return runScan(cfg, sub, jsonMode, start)
	case "issues":
		return runIssues(cfg, sub, jsonMode, start)
	case "rpc":
		return runRPC(cfg, sub, jsonMode, start)
	case "daemon":
		return runDaemon(cfg, sub, jsonMode, start)
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown command: " + cmd}
	}
}

func runDaemon(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "daemon subcommand required"}
	}
	sub := args[0]

	switch sub {
	case "run":
		logFile, err := os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
		}
		defer logFile.Close()
		logger := log.New(logFile, "[agent-burp-daemon] ", log.LstdFlags)
		srv := daemon.NewServer(cfg, logger)
		return srv.Run(context.Background())
	case "status":
		c := daemon.NewClient(cfg.DaemonSocketPath, time.Duration(cfg.RequestTimeoutMS)*time.Millisecond)
		resp, err := c.Send(context.Background(), protocol.IPCRequest{Action: "status"})
		if err != nil {
			return &appError{ExitCode: exitConnect, Code: "DAEMON_NOT_RUNNING", Message: err.Error()}
		}
		return printSuccess(jsonMode, "daemon status", resp.Result, start)
	case "stop":
		c := daemon.NewClient(cfg.DaemonSocketPath, time.Duration(cfg.RequestTimeoutMS)*time.Millisecond)
		_, err := c.Send(context.Background(), protocol.IPCRequest{Action: "shutdown"})
		if err != nil {
			return &appError{ExitCode: exitConnect, Code: "DAEMON_STOP_ERROR", Message: err.Error()}
		}
		return printSuccess(jsonMode, "daemon stop", map[string]any{"stopped": true}, start)
	case "restart":
		c := daemon.NewClient(cfg.DaemonSocketPath, time.Duration(cfg.RequestTimeoutMS)*time.Millisecond)
		_, _ = c.Send(context.Background(), protocol.IPCRequest{Action: "shutdown"})
		if err := startDaemon(cfg); err != nil {
			return err
		}
		return printSuccess(jsonMode, "daemon restart", map[string]any{"restarted": true}, start)
	case "logs":
		b, err := os.ReadFile(cfg.LogPath)
		if err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
		}
		if jsonMode {
			return printSuccess(jsonMode, "daemon logs", map[string]any{"logs": string(b)}, start)
		}
		fmt.Print(string(b))
		return nil
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown daemon subcommand: " + sub}
	}
}

func runDoctor(cfg config.Config, jsonMode bool, start time.Time) error {
	if err := ensureDaemon(cfg); err != nil {
		return err
	}
	c := daemon.NewClient(cfg.DaemonSocketPath, time.Duration(cfg.RequestTimeoutMS)*time.Millisecond)
	statusResp, err := c.Send(context.Background(), protocol.IPCRequest{Action: "status"})
	if err != nil {
		return &appError{ExitCode: exitConnect, Code: "DAEMON_ERROR", Message: err.Error()}
	}
	openResp, err := c.Send(context.Background(), protocol.IPCRequest{Action: "open"})
	if err != nil {
		return &appError{ExitCode: exitConnect, Code: "BURP_CONNECT_ERROR", Message: err.Error()}
	}
	if !openResp.OK {
		return ipcToAppError(openResp.Error)
	}

	out := map[string]any{
		"daemon":         statusResp.Result,
		"burp_connected": openResp.BurpConn,
		"ws_url":         cfg.BurpWSURL,
		"socket":         cfg.DaemonSocketPath,
	}
	return printSuccess(jsonMode, "doctor", out, start)
}

func runCapabilities(cfg config.Config, jsonMode bool, start time.Time) error {
	data, err := callBurp(cfg, "get_capabilities", map[string]any{})
	if err != nil {
		return err
	}
	return printSuccess(jsonMode, "capabilities", data, start)
}

func runOpen(cfg config.Config, jsonMode bool, start time.Time) error {
	if err := ensureDaemon(cfg); err != nil {
		return err
	}
	c := daemon.NewClient(cfg.DaemonSocketPath, time.Duration(cfg.RequestTimeoutMS)*time.Millisecond)
	resp, err := c.Send(context.Background(), protocol.IPCRequest{Action: "open"})
	if err != nil {
		return &appError{ExitCode: exitConnect, Code: "BURP_CONNECT_ERROR", Message: err.Error()}
	}
	if !resp.OK {
		return ipcToAppError(resp.Error)
	}
	return printSuccess(jsonMode, "open", resp.Result, start)
}

func runClose(cfg config.Config, jsonMode bool, start time.Time) error {
	if err := ensureDaemon(cfg); err != nil {
		return err
	}
	c := daemon.NewClient(cfg.DaemonSocketPath, time.Duration(cfg.RequestTimeoutMS)*time.Millisecond)
	resp, err := c.Send(context.Background(), protocol.IPCRequest{Action: "close"})
	if err != nil {
		return &appError{ExitCode: exitConnect, Code: "DAEMON_ERROR", Message: err.Error()}
	}
	return printSuccess(jsonMode, "close", resp.Result, start)
}

func runRequest(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var urlVal, method, body, bodyFile, bodyBase64, contentType, source string
	var addToSiteMap, bodyStdin, binary bool
	var headers headerFlags
	fs.StringVar(&urlVal, "url", "", "target URL")
	fs.StringVar(&method, "method", "", "HTTP method")
	fs.Var(&headers, "header", "header K: V")
	fs.StringVar(&body, "body", "", "body string")
	fs.StringVar(&bodyFile, "body-file", "", "body file")
	fs.BoolVar(&bodyStdin, "body-stdin", false, "read body from stdin")
	fs.StringVar(&bodyBase64, "body-base64", "", "base64 encoded body")
	fs.BoolVar(&binary, "binary", false, "base64-encode file/stdin bytes")
	fs.StringVar(&contentType, "content-type", "", "content type")
	fs.BoolVar(&addToSiteMap, "add-to-sitemap", false, "add request/response to sitemap")
	fs.StringVar(&source, "source", defaultReqName, "source label")

	if err := fs.Parse(args); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}
	if urlVal == "" {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--url required"}
	}
	if _, err := parseURL(urlVal); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: err.Error()}
	}

	bodySources := 0
	for _, on := range []bool{body != "", bodyFile != "", bodyStdin, bodyBase64 != ""} {
		if on {
			bodySources++
		}
	}
	if bodySources > 1 {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "only one of --body, --body-file, --body-stdin, --body-base64 is allowed"}
	}

	hdrMap, err := parseHeaders(headers)
	if err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: err.Error()}
	}

	if method == "" {
		if bodySources > 0 {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	method = strings.ToUpper(method)

	payload := map[string]any{
		"url":          urlVal,
		"method":       method,
		"headers":      hdrMap,
		"addToSiteMap": addToSiteMap,
		"source":       source,
	}

	if body != "" {
		payload["body"] = body
	}
	if bodyFile != "" {
		b, err := os.ReadFile(bodyFile)
		if err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
		}
		if binary {
			payload["bodyBase64"] = base64.StdEncoding.EncodeToString(b)
		} else {
			payload["body"] = string(b)
		}
	}
	if bodyStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
		}
		if binary {
			payload["bodyBase64"] = base64.StdEncoding.EncodeToString(b)
		} else {
			payload["body"] = string(b)
		}
	}
	if bodyBase64 != "" {
		payload["bodyBase64"] = bodyBase64
	}

	if contentType != "" {
		hdrMap["Content-Type"] = contentType
	} else if _, ok := payload["body"]; ok {
		b := payload["body"].(string)
		if _, exists := hdrMap["Content-Type"]; !exists {
			if json.Valid([]byte(b)) {
				hdrMap["Content-Type"] = "application/json"
			} else {
				hdrMap["Content-Type"] = "text/plain; charset=utf-8"
			}
		}
	}

	data, err := callBurp(cfg, "send_request", payload)
	if err != nil {
		return err
	}
	return printSuccess(jsonMode, "request", redactSensitive(data), start)
}

func runHTTP1(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	fs := flag.NewFlagSet("http1", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var host, req, reqFile string
	var port int
	var https, reqStdin bool
	fs.StringVar(&host, "host", "", "target hostname")
	fs.IntVar(&port, "port", 443, "target port")
	fs.BoolVar(&https, "https", true, "use HTTPS")
	fs.StringVar(&req, "request", "", "raw HTTP request")
	fs.StringVar(&reqFile, "request-file", "", "path to raw HTTP request")
	fs.BoolVar(&reqStdin, "request-stdin", false, "read raw HTTP request from stdin")
	if err := fs.Parse(args); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}
	if host == "" {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--host required"}
	}

	content, err := readInputSource(req, reqFile, reqStdin)
	if err != nil {
		return err
	}

	data, callErr := callBurp(cfg, "send_http1_request", map[string]any{
		"targetHostname": host,
		"targetPort":     port,
		"usesHttps":      https,
		"content":        content,
	})
	if callErr != nil {
		return callErr
	}
	return printSuccess(jsonMode, "http1", redactSensitive(data), start)
}

func runHTTP2(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	fs := flag.NewFlagSet("http2", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var host, body, bodyFile string
	var port int
	var https, bodyStdin bool
	var pseudoHeaders kvFlags
	var headers kvFlags
	fs.StringVar(&host, "host", "", "target hostname")
	fs.IntVar(&port, "port", 443, "target port")
	fs.BoolVar(&https, "https", true, "use HTTPS")
	fs.Var(&pseudoHeaders, "pseudo", "pseudo header key:value (repeatable)")
	fs.Var(&headers, "header", "header key:value (repeatable)")
	fs.StringVar(&body, "body", "", "request body")
	fs.StringVar(&bodyFile, "body-file", "", "request body file")
	fs.BoolVar(&bodyStdin, "body-stdin", false, "read body from stdin")
	if err := fs.Parse(args); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}
	if host == "" {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--host required"}
	}

	bodySources := 0
	for _, on := range []bool{body != "", bodyFile != "", bodyStdin} {
		if on {
			bodySources++
		}
	}
	if bodySources > 1 {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "only one of --body, --body-file, --body-stdin is allowed"}
	}
	if bodyFile != "" {
		b, err := os.ReadFile(bodyFile)
		if err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
		}
		body = string(b)
	}
	if bodyStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
		}
		body = string(b)
	}

	pseudoMap, err := parseKeyValuePairs(pseudoHeaders)
	if err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: err.Error()}
	}
	hdrMap, err := parseKeyValuePairs(headers)
	if err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: err.Error()}
	}

	data, callErr := callBurp(cfg, "send_http2_request", map[string]any{
		"targetHostname": host,
		"targetPort":     port,
		"usesHttps":      https,
		"pseudoHeaders":  pseudoMap,
		"headers":        hdrMap,
		"requestBody":    body,
	})
	if callErr != nil {
		return callErr
	}
	return printSuccess(jsonMode, "http2", redactSensitive(data), start)
}

func runEditor(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "editor subcommand required: get|set"}
	}
	switch args[0] {
	case "get":
		data, err := callBurp(cfg, "get_active_editor_contents", map[string]any{})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "editor get", data, start)
	case "set":
		fs := flag.NewFlagSet("editor set", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var text string
		var stdin bool
		fs.StringVar(&text, "text", "", "editor text")
		fs.BoolVar(&stdin, "stdin", false, "read text from stdin")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if stdin {
			b, err := io.ReadAll(os.Stdin)
			if err != nil {
				return &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
			}
			text = string(b)
		}
		if text == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--text or --stdin required"}
		}
		data, err := callBurp(cfg, "set_active_editor_contents", map[string]any{"text": text})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "editor set", data, start)
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown editor subcommand: " + args[0]}
	}
}

func runRuntime(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "runtime subcommand required: task-engine|intercept"}
	}
	switch args[0] {
	case "task-engine":
		fs := flag.NewFlagSet("runtime task-engine", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var runningRaw string
		fs.StringVar(&runningRaw, "running", "true", "set running state (true|false)")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		running, err := parseBoolString(runningRaw)
		if err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: err.Error()}
		}
		data, err := callBurp(cfg, "set_task_execution_engine_state", map[string]any{"running": running})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "runtime task-engine", data, start)
	case "intercept":
		fs := flag.NewFlagSet("runtime intercept", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var onRaw string
		fs.StringVar(&onRaw, "on", "true", "enable or disable intercept (true|false)")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		on, err := parseBoolString(onRaw)
		if err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: err.Error()}
		}
		data, err := callBurp(cfg, "set_proxy_intercept_state", map[string]any{"intercepting": on})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "runtime intercept", data, start)
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown runtime subcommand: " + args[0]}
	}
}

func runTransform(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "transform subcommand required: url-encode|url-decode|base64-encode|base64-decode|random"}
	}
	switch args[0] {
	case "url-encode", "url-decode", "base64-encode", "base64-decode":
		fs := flag.NewFlagSet("transform", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var content string
		var stdin bool
		fs.StringVar(&content, "content", "", "input content")
		fs.BoolVar(&stdin, "stdin", false, "read input from stdin")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if stdin {
			b, err := io.ReadAll(os.Stdin)
			if err != nil {
				return &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
			}
			content = string(b)
		}
		if content == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--content or --stdin required"}
		}

		method := map[string]string{
			"url-encode":    "url_encode",
			"url-decode":    "url_decode",
			"base64-encode": "base64_encode",
			"base64-decode": "base64_decode",
		}[args[0]]

		data, err := callBurp(cfg, method, map[string]any{"content": content})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "transform "+args[0], data, start)
	case "random":
		fs := flag.NewFlagSet("transform random", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var length int
		var characterSet string
		fs.IntVar(&length, "length", 16, "string length")
		fs.StringVar(&characterSet, "charset", "ALPHANUMERIC", "character set")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		data, err := callBurp(cfg, "generate_random_string", map[string]any{"length": length, "characterSet": characterSet})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "transform random", data, start)
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown transform subcommand: " + args[0]}
	}
}

func runWSHistory(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	fs := flag.NewFlagSet("ws-history", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var regex string
	var limit, offset int
	fs.StringVar(&regex, "regex", "", "regex filter")
	fs.IntVar(&limit, "limit", 50, "max items")
	fs.IntVar(&offset, "offset", 0, "offset")
	if err := fs.Parse(args); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}

	if regex == "" {
		data, err := callBurp(cfg, "get_proxy_websocket_history", map[string]any{"limit": limit, "offset": offset})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "ws-history", data, start)
	}

	data, err := callBurp(cfg, "get_proxy_websocket_history_regex", map[string]any{"regex": regex, "limit": limit, "offset": offset})
	if err != nil {
		return err
	}
	return printSuccess(jsonMode, "ws-history", data, start)
}

func runHistory(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var domain, method string
	var limit, status int
	fs.StringVar(&domain, "domain", "", "target domain")
	fs.IntVar(&limit, "limit", 20, "max records")
	fs.StringVar(&method, "method", "", "method filter")
	fs.IntVar(&status, "status", 0, "status filter")
	if err := fs.Parse(args); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}
	if domain == "" {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--domain required"}
	}
	params := map[string]any{"domain": domain, "limit": limit}
	if method != "" {
		params["method"] = strings.ToUpper(method)
	}
	if status > 0 {
		params["statusCode"] = status
	}
	data, err := callBurp(cfg, "get_proxy_history", params)
	if err != nil {
		return err
	}
	return printSuccess(jsonMode, "history", redactSensitive(data), start)
}

func runSitemap(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	fs := flag.NewFlagSet("sitemap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var domain string
	var includeParams bool
	fs.StringVar(&domain, "domain", "", "domain filter")
	fs.BoolVar(&includeParams, "include-params", true, "include parameters")
	if err := fs.Parse(args); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}
	params := map[string]any{"includeParams": includeParams}
	if domain != "" {
		params["domain"] = domain
	}
	data, err := callBurp(cfg, "get_sitemap", params)
	if err != nil {
		return err
	}
	return printSuccess(jsonMode, "sitemap", data, start)
}

func runScope(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "scope subcommand required: get|add|remove"}
	}
	switch args[0] {
	case "get":
		fs := flag.NewFlagSet("scope get", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var urlVal string
		fs.StringVar(&urlVal, "url", "", "URL to check")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		params := map[string]any{}
		if urlVal != "" {
			params["url"] = urlVal
		}
		data, err := callBurp(cfg, "get_scope", params)
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "scope get", data, start)
	case "add", "remove":
		fs := flag.NewFlagSet("scope modify", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var urlVal string
		fs.StringVar(&urlVal, "url", "", "URL")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if urlVal == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--url required"}
		}
		data, err := callBurp(cfg, "modify_scope", map[string]any{"action": args[0], "url": urlVal})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "scope "+args[0], data, start)
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown scope subcommand: " + args[0]}
	}
}

func runRepeater(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	params, err := parseRawRequestCommand("repeater", args)
	if err != nil {
		return err
	}
	data, callErr := callBurp(cfg, "send_to_repeater", params)
	if callErr != nil {
		return callErr
	}
	return printSuccess(jsonMode, "repeater", data, start)
}

func runIntruder(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	params, err := parseRawRequestCommand("intruder", args)
	if err != nil {
		return err
	}
	data, callErr := callBurp(cfg, "send_to_intruder", params)
	if callErr != nil {
		return callErr
	}
	return printSuccess(jsonMode, "intruder", data, start)
}

func runScan(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "scan subcommand required: start|stop"}
	}
	switch args[0] {
	case "start":
		fs := flag.NewFlagSet("scan start", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var urlVal string
		var crawl bool
		fs.StringVar(&urlVal, "url", "", "target URL")
		fs.BoolVar(&crawl, "crawl", false, "enable crawl before audit")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if urlVal == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--url required"}
		}
		data, err := callBurp(cfg, "start_scan", map[string]any{"url": urlVal, "crawl": crawl})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "scan start", data, start)
	case "stop":
		fs := flag.NewFlagSet("scan stop", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var id string
		fs.StringVar(&id, "id", "", "scan ID")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if id == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--id required"}
		}
		data, err := callBurp(cfg, "stop_scan", map[string]any{"scanId": id})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "scan stop", data, start)
	case "status":
		fs := flag.NewFlagSet("scan status", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var id string
		fs.StringVar(&id, "id", "", "scan ID")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if id == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--id required"}
		}
		data, err := callBurp(cfg, "get_scan_status", map[string]any{"scanId": id})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "scan status", data, start)
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown scan subcommand: " + args[0]}
	}
}

func runJob(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "job subcommand required: status|list|cancel"}
	}
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("job status", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var id string
		fs.StringVar(&id, "id", "", "job ID")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if id == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--id required"}
		}
		data, err := callBurp(cfg, "get_job_status", map[string]any{"jobId": id})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "job status", data, start)
	case "list":
		data, err := callBurp(cfg, "list_jobs", map[string]any{})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "job list", data, start)
	case "cancel":
		fs := flag.NewFlagSet("job cancel", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var id string
		fs.StringVar(&id, "id", "", "job ID")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if id == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--id required"}
		}
		data, err := callBurp(cfg, "cancel_job", map[string]any{"jobId": id})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "job cancel", data, start)
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown job subcommand: " + args[0]}
	}
}

func runCrawl(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 || args[0] != "start" {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "crawl subcommand required: start"}
	}
	fs := flag.NewFlagSet("crawl start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var urlVal string
	fs.StringVar(&urlVal, "url", "", "target URL")
	if err := fs.Parse(args[1:]); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}
	if urlVal == "" {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--url required"}
	}
	data, err := callBurp(cfg, "start_crawl", map[string]any{"url": urlVal})
	if err != nil {
		return err
	}
	return printSuccess(jsonMode, "crawl start", data, start)
}

func runExport(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 || args[0] != "start" {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "export subcommand required: start"}
	}
	fs := flag.NewFlagSet("export start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var exportType, outPath, domain string
	var limit int
	fs.StringVar(&exportType, "type", "proxy_history", "export type")
	fs.StringVar(&outPath, "out", "", "output path")
	fs.StringVar(&domain, "domain", "", "domain for proxy_history")
	fs.IntVar(&limit, "limit", 500, "record limit")
	if err := fs.Parse(args[1:]); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}
	if outPath == "" {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--out required"}
	}
	params := map[string]any{"exportType": exportType, "outputPath": outPath, "limit": limit}
	if domain != "" {
		params["domain"] = domain
	}
	data, err := callBurp(cfg, "start_bulk_export", params)
	if err != nil {
		return err
	}
	return printSuccess(jsonMode, "export start", data, start)
}

func runReplay(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "replay subcommand required: export|run"}
	}
	switch args[0] {
	case "export":
		fs := flag.NewFlagSet("replay export", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var outPath, domain string
		var limit int
		fs.StringVar(&outPath, "out", "", "output path")
		fs.StringVar(&domain, "domain", "", "domain")
		fs.IntVar(&limit, "limit", 500, "request limit")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if outPath == "" || domain == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--out and --domain required"}
		}
		data, err := callBurp(cfg, "export_replay_pack", map[string]any{"outputPath": outPath, "domain": domain, "limit": limit})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "replay export", data, start)
	case "run":
		fs := flag.NewFlagSet("replay run", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var inPath string
		fs.StringVar(&inPath, "in", "", "input replay pack path")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		if inPath == "" {
			return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "--in required"}
		}
		data, err := callBurp(cfg, "run_replay_pack", map[string]any{"inputPath": inPath})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "replay run", data, start)
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown replay subcommand: " + args[0]}
	}
}

func runEvents(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "events subcommand required: subscribe|unsubscribe|status"}
	}
	switch args[0] {
	case "subscribe", "unsubscribe":
		fs := flag.NewFlagSet("events", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var typesCSV string
		fs.StringVar(&typesCSV, "types", "*", "comma-separated event types")
		if err := fs.Parse(args[1:]); err != nil {
			return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
		}
		types := []any{}
		for _, t := range strings.Split(typesCSV, ",") {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				types = append(types, trimmed)
			}
		}
		method := "subscribe_events"
		if args[0] == "unsubscribe" {
			method = "unsubscribe_events"
		}
		data, err := callBurp(cfg, method, map[string]any{"eventTypes": types})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "events "+args[0], data, start)
	case "status":
		data, err := callBurp(cfg, "get_event_subscriptions", map[string]any{})
		if err != nil {
			return err
		}
		return printSuccess(jsonMode, "events status", data, start)
	default:
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "unknown events subcommand: " + args[0]}
	}
}

func runIssues(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	fs := flag.NewFlagSet("issues", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var severity, urlFilter string
	var limit, offset int
	fs.StringVar(&severity, "severity", "", "severity filter")
	fs.StringVar(&urlFilter, "url", "", "URL contains filter")
	fs.IntVar(&limit, "limit", 100, "limit")
	fs.IntVar(&offset, "offset", 0, "offset")
	if err := fs.Parse(args); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}

	params := map[string]any{"limit": limit, "offset": offset}
	if severity != "" {
		params["severity"] = strings.ToUpper(severity)
	}
	if urlFilter != "" {
		params["url"] = urlFilter
	}
	data, err := callBurp(cfg, "get_scanner_issues", params)
	if err != nil {
		return err
	}
	return printSuccess(jsonMode, "issues", redactSensitive(data), start)
}

func runRPC(cfg config.Config, args []string, jsonMode bool, start time.Time) error {
	if len(args) == 0 {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: "rpc method required"}
	}

	method := args[0]
	fs := flag.NewFlagSet("rpc", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var paramsArg string
	fs.StringVar(&paramsArg, "params", "{}", "JSON object or @file")
	if err := fs.Parse(args[1:]); err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}

	params, err := parseParamsArg(paramsArg)
	if err != nil {
		return &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: err.Error()}
	}

	data, callErr := callBurp(cfg, method, params)
	if callErr != nil {
		return callErr
	}
	return printSuccess(jsonMode, "rpc", redactSensitive(data), start)
}

func ensureDaemon(cfg config.Config) error {
	timeout := time.Duration(cfg.RequestTimeoutMS) * time.Millisecond
	c := daemon.NewClient(cfg.DaemonSocketPath, timeout)
	if _, err := c.Send(context.Background(), protocol.IPCRequest{Action: "ping"}); err == nil {
		return nil
	}
	return startDaemon(cfg)
}

func startDaemon(cfg config.Config) error {
	exe, err := os.Executable()
	if err != nil {
		return &appError{ExitCode: exitConnect, Code: "DAEMON_START_ERROR", Message: err.Error()}
	}
	logFile, err := os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return &appError{ExitCode: exitConnect, Code: "DAEMON_START_ERROR", Message: err.Error()}
	}

	cmd := exec.Command(exe, "daemon", "run")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return &appError{ExitCode: exitConnect, Code: "DAEMON_START_ERROR", Message: err.Error()}
	}
	_ = cmd.Process.Release()
	_ = logFile.Close()

	deadline := time.Now().Add(3 * time.Second)
	c := daemon.NewClient(cfg.DaemonSocketPath, 300*time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := c.Send(context.Background(), protocol.IPCRequest{Action: "ping"}); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return &appError{ExitCode: exitConnect, Code: "DAEMON_START_ERROR", Message: "daemon failed to start"}
}

func callBurp(cfg config.Config, method string, params map[string]any) (any, error) {
	if err := ensureDaemon(cfg); err != nil {
		return nil, err
	}

	c := daemon.NewClient(cfg.DaemonSocketPath, time.Duration(cfg.RequestTimeoutMS)*time.Millisecond)
	ctx := context.Background()
	resp, err := c.Send(ctx, protocol.IPCRequest{Action: "call", Method: method, Params: params, TimeoutMS: cfg.RequestTimeoutMS})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "timeout") {
			return nil, &appError{ExitCode: exitTimeout, Code: "TIMEOUT", Message: err.Error()}
		}
		return nil, &appError{ExitCode: exitConnect, Code: "DAEMON_ERROR", Message: err.Error()}
	}
	if !resp.OK {
		return nil, ipcToAppError(resp.Error)
	}
	return resp.Result, nil
}

func parseHeaders(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, h := range values {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header format: %s", h)
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if k == "" {
			return nil, fmt.Errorf("invalid header name in: %s", h)
		}
		out[k] = v
	}
	return out, nil
}

func parseKeyValuePairs(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range values {
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key:value format: %s", item)
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if k == "" {
			return nil, fmt.Errorf("invalid key in: %s", item)
		}
		out[k] = v
	}
	return out, nil
}

func readInputSource(raw, filePath string, fromStdin bool) (string, error) {
	sources := 0
	for _, on := range []bool{raw != "", filePath != "", fromStdin} {
		if on {
			sources++
		}
	}
	if sources == 0 {
		return "", &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "provide one of --request, --request-file, --request-stdin"}
	}
	if sources > 1 {
		return "", &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "request input sources are mutually exclusive"}
	}
	if raw != "" {
		return raw, nil
	}
	if filePath != "" {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return "", &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
		}
		return string(b), nil
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
	}
	return string(b), nil
}

func parseBoolString(value string) (bool, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	switch v {
	case "true", "1", "yes", "on", "enabled":
		return true, nil
	case "false", "0", "no", "off", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", value)
	}
}

func parseRawRequestCommand(name string, args []string) (map[string]any, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var reqRaw, reqFile, urlVal, method string
	var body, tabName string
	var bodyStdin, https bool
	var port int
	var headers headerFlags
	fs.StringVar(&reqRaw, "request", "", "raw HTTP request")
	fs.StringVar(&reqFile, "request-file", "", "path to raw request file")
	fs.BoolVar(&bodyStdin, "request-stdin", false, "read raw request from stdin")
	fs.StringVar(&urlVal, "url", "", "target URL (alternative to --request)")
	fs.StringVar(&method, "method", "GET", "HTTP method for --url mode")
	fs.Var(&headers, "header", "header K:V for --url mode")
	fs.StringVar(&body, "body", "", "body for --url mode")
	fs.StringVar(&tabName, "tab-name", "", "optional tab name")
	fs.BoolVar(&https, "https", true, "target uses https")
	fs.IntVar(&port, "port", 0, "target port")

	if err := fs.Parse(args); err != nil {
		return nil, &appError{ExitCode: exitBadArgs, Code: "BAD_ARGS", Message: err.Error()}
	}

	src := 0
	for _, on := range []bool{reqRaw != "", reqFile != "", bodyStdin, urlVal != ""} {
		if on {
			src++
		}
	}
	if src == 0 {
		return nil, &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "provide one of --request, --request-file, --request-stdin, --url"}
	}
	if src > 1 {
		return nil, &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: "request input sources are mutually exclusive"}
	}

	var requestText, host string
	if reqRaw != "" {
		requestText = reqRaw
	} else if reqFile != "" {
		b, err := os.ReadFile(reqFile)
		if err != nil {
			return nil, &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
		}
		requestText = string(b)
	} else if bodyStdin {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, &appError{ExitCode: exitBadArgs, Code: "IO_ERROR", Message: err.Error()}
		}
		requestText = string(b)
	} else {
		u, err := parseURL(urlVal)
		if err != nil {
			return nil, &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: err.Error()}
		}
		host = u.Hostname()
		https = u.Scheme == "https"
		if port == 0 {
			if u.Port() != "" {
				fmt.Sscanf(u.Port(), "%d", &port)
			} else if https {
				port = 443
			} else {
				port = 80
			}
		}
		hdrMap, err := parseHeaders(headers)
		if err != nil {
			return nil, err
		}
		requestText = buildRawRequest(u, strings.ToUpper(method), hdrMap, body)
	}

	if host == "" {
		parsedHost, parsedPort, parsedHTTPS, err := inferHostPortFromRaw(requestText, https, port)
		if err != nil {
			return nil, &appError{ExitCode: exitBadArgs, Code: "VALIDATION_ERROR", Message: err.Error()}
		}
		host, port, https = parsedHost, parsedPort, parsedHTTPS
	}
	if port == 0 {
		if https {
			port = 443
		} else {
			port = 80
		}
	}

	params := map[string]any{"request": requestText, "host": host, "port": port, "https": https}
	if tabName != "" {
		params["tabName"] = tabName
	}
	return params, nil
}

func parseURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("URL must use http or https")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("URL host required")
	}
	return u, nil
}

func buildRawRequest(u *url.URL, method string, headers map[string]string, body string) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	lines := []string{fmt.Sprintf("%s %s HTTP/1.1", method, path)}
	if _, ok := headers["Host"]; !ok {
		headers["Host"] = u.Host
	}
	for k, v := range headers {
		lines = append(lines, fmt.Sprintf("%s: %s", k, v))
	}
	if body != "" {
		if _, ok := headers["Content-Length"]; !ok {
			lines = append(lines, fmt.Sprintf("Content-Length: %d", len(body)))
		}
	}
	return strings.Join(lines, "\r\n") + "\r\n\r\n" + body
}

func inferHostPortFromRaw(raw string, https bool, port int) (string, int, bool, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for _, l := range lines {
		if strings.HasPrefix(strings.ToLower(l), "host:") {
			hostport := strings.TrimSpace(l[5:])
			if strings.Contains(hostport, ":") {
				host, p, err := netSplitHostPortLoose(hostport)
				if err == nil {
					if p == 443 {
						return host, p, true, nil
					}
					return host, p, https, nil
				}
			}
			return hostport, port, https, nil
		}
	}
	return "", 0, https, fmt.Errorf("host not provided; include Host header or use --url")
}

func netSplitHostPortLoose(v string) (string, int, error) {
	parts := strings.Split(v, ":")
	if len(parts) < 2 {
		return "", 0, fmt.Errorf("missing port")
	}
	p := 0
	_, err := fmt.Sscanf(parts[len(parts)-1], "%d", &p)
	if err != nil {
		return "", 0, err
	}
	return strings.Join(parts[:len(parts)-1], ":"), p, nil
}

func parseParamsArg(v string) (map[string]any, error) {
	raw := v
	if strings.HasPrefix(v, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(v, "@"))
		if err != nil {
			return nil, err
		}
		raw = string(b)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func ipcToAppError(err *protocol.IPCError) error {
	if err == nil {
		return &appError{ExitCode: exitRPC, Code: "BURP_RPC_ERROR", Message: "unknown RPC error"}
	}
	exit := exitRPC
	if strings.Contains(strings.ToLower(err.Message), "timed out") {
		exit = exitTimeout
	}
	if err.Code == "BURP_CONNECT_ERROR" {
		exit = exitConnect
	}
	return &appError{ExitCode: exit, Code: err.Code, Message: err.Message, Details: err.Details}
}

func redactSensitive(data any) any {
	b, err := json.Marshal(data)
	if err != nil {
		return data
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return data
	}
	redactWalk(v)
	return v
}

func redactWalk(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			lk := strings.ToLower(k)
			if lk == "authorization" || lk == "cookie" || lk == "set-cookie" {
				t[k] = "<redacted>"
				continue
			}
			redactWalk(vv)
		}
	case []any:
		for _, item := range t {
			redactWalk(item)
		}
	}
}

func printSuccess(jsonMode bool, command string, data any, start time.Time) error {
	if jsonMode {
		env := protocol.Envelope{
			Success: true,
			Data:    data,
			Meta: &protocol.MetaBody{
				Command:    command,
				DurationMS: time.Since(start).Milliseconds(),
			},
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(env)
	}
	pretty, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(pretty))
	return nil
}

func printErrorEnvelope(ae *appError, start time.Time) {
	// If global parsing failed we cannot read --json reliably; emit plain stderr by default.
	asJSON := hasJSONFlag(os.Args[1:])
	if asJSON {
		env := protocol.Envelope{
			Success: false,
			Error: &protocol.ErrBody{
				Code:    ae.Code,
				Message: ae.Message,
				Details: ae.Details,
			},
			Meta: &protocol.MetaBody{
				Command:    strings.Join(os.Args[1:], " "),
				DurationMS: time.Since(start).Milliseconds(),
			},
		}
		enc := json.NewEncoder(os.Stderr)
		enc.SetIndent("", "  ")
		_ = enc.Encode(env)
		return
	}
	fmt.Fprintf(os.Stderr, "error [%s]: %s\n", ae.Code, ae.Message)
}

func hasJSONFlag(args []string) bool {
	for _, a := range args {
		if a == "--json" || a == "--output=json" {
			return true
		}
	}
	return false
}

func extractGlobalArgs(args []string) ([]string, []string) {
	boolFlags := map[string]bool{"--json": true, "--debug": true}
	valueFlags := map[string]bool{"--config": true, "--ws-url": true, "--auth-token": true, "--timeout": true, "--output": true}

	globals := make([]string, 0, len(args))
	rest := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if boolFlags[arg] {
			globals = append(globals, arg)
			continue
		}

		matchedEq := false
		for key := range valueFlags {
			if strings.HasPrefix(arg, key+"=") {
				globals = append(globals, arg)
				matchedEq = true
				break
			}
		}
		if matchedEq {
			continue
		}

		if valueFlags[arg] {
			globals = append(globals, arg)
			if i+1 < len(args) {
				globals = append(globals, args[i+1])
				i++
			}
			continue
		}

		rest = append(rest, arg)
	}

	return globals, rest
}

func printUsage() {
	exe := filepath.Base(os.Args[0])
	fmt.Printf(`%s - Burp CLI for agents and scripts

Commands:
  doctor
  capabilities
  open
  close
  request
  http1
  http2
  transform url-encode|url-decode|base64-encode|base64-decode|random
  ws-history [--regex]
  editor get|set
  runtime task-engine|intercept
  job status|list|cancel
  crawl start
  export start
  replay export|run
  events subscribe|unsubscribe|status
  history
  sitemap
  scope get|add|remove
  repeater
  intruder
  scan start|status|stop
  issues
  rpc <method>
  daemon run|status|stop|restart|logs

Global flags:
  --json --timeout <ms> --ws-url <url> --auth-token <token> --config <path> --debug

Examples:
  %s open --json
  %s request --url https://example.com/api --method POST --body '{"k":"v"}' --json
  %s history --domain example.com --limit 20 --json
`, exe, exe, exe, exe)
}
