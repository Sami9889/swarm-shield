package lang_test

import (
	"testing"

	"swarm-shield/internal/lang"
)

func TestLexer(t *testing.T) {
	input := `define rate_limit "default" {
    limit = 100
    window = 1m
}`
	lexer := lang.NewLexer(input)
	tokens, err := lexer.Tokenize()
	if err != nil {
		t.Fatalf("lexer error: %v", err)
	}
	if len(tokens) < 5 {
		t.Fatalf("expected at least 5 tokens, got %d", len(tokens))
	}
}

func TestParser(t *testing.T) {
	input := `define acl "internal" {
    if $ip starts_with "10." {
        allow
    }
    deny
}`
	lexer := lang.NewLexer(input)
	tokens, err := lexer.Tokenize()
	if err != nil {
		t.Fatalf("lexer error: %v", err)
	}
	parser := lang.NewParser(tokens)
	program, err := parser.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(program.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(program.Rules))
	}
}

func TestEvaluatorACL(t *testing.T) {
	input := `define acl "internal" {
    if $ip starts_with "10." {
        allow
    }
    deny
}`
	lexer := lang.NewLexer(input)
	tokens, err := lexer.Tokenize()
	if err != nil {
		t.Fatalf("lexer error: %v", err)
	}
	parser := lang.NewParser(tokens)
	program, err := parser.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	ev := lang.NewEvaluator(program.Rules)

	ctx := &lang.EventContext{
		Request: &lang.HTTPRequest{
			Method:  "GET",
			Path:    "/api/data",
			Header:  nil,
		},
		IPAddress: "10.0.0.1",
	}
	result := ev.EvaluateACL("internal", ctx)
	if result.Action != "allow" {
		t.Fatalf("expected allow for 10.0.0.1, got %s", result.Action)
	}

	ctx.IPAddress = "192.168.1.1"
	result = ev.EvaluateACL("internal", ctx)
	if result.Action != "deny" {
		t.Fatalf("expected deny for 192.168.1.1, got %s", result.Action)
	}
}

func TestEvaluatorRateLimit(t *testing.T) {
	input := `define rate_limit "strict" {
    limit = 5
    window = "30s"
    key = "ip"
}`
	lexer := lang.NewLexer(input)
	tokens, err := lexer.Tokenize()
	if err != nil {
		t.Fatalf("lexer error: %v", err)
	}
	parser := lang.NewParser(tokens)
	program, err := parser.Parse()
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	ev := lang.NewEvaluator(program.Rules)

	limit, window, key := ev.EvaluateRateLimit("strict")
	if limit != 5 {
		t.Fatalf("expected limit 5, got %d", limit)
	}
	if window != 30 {
		t.Fatalf("expected window 30, got %d", window)
	}
	if key != "ip" {
		t.Fatalf("expected key ip, got %s", key)
	}
}
