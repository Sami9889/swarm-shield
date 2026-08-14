package lang

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Registry struct {
	evaluators map[string]*Evaluator
}

func NewRegistry() *Registry {
	return &Registry{evaluators: make(map[string]*Evaluator)}
}

func (r *Registry) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lexer := NewLexer(string(data))
	tokens, err := lexer.Tokenize()
	if err != nil {
		return fmt.Errorf("lexer error in %s: %w", path, err)
	}

	parser := NewParser(tokens)
	program, err := parser.Parse()
	if err != nil {
		return fmt.Errorf("parse error in %s: %w", path, err)
	}

	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	r.evaluators[base] = NewEvaluator(program.Rules)
	return nil
}

func (r *Registry) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".swarm") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := r.LoadFile(path); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) Evaluator(name string) (*Evaluator, bool) {
	ev, ok := r.evaluators[name]
	return ev, ok
}

func (r *Registry) AllEvaluators() map[string]*Evaluator {
	return r.evaluators
}
