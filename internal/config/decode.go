package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// Decode overlays only present TOML fields onto Defaults. Explicit false, zero,
// empty, and source-inapplicable values are never replaced by defaults. A schema
// version must be supplied, even for an otherwise empty browsing configuration.
func Decode(data []byte, filename string) (Config, error) {
	cfg := Defaults()
	cfg.SchemaVersion = 0
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, decodeError(filename, err)
	}
	locations := sourceLocations(data)
	// The library also matches struct fields case-insensitively. Every public
	// schema key is lowercase; reject folded aliases so TOML's case-sensitive
	// names cannot bypass strict unknown-key checking or shadow another setting.
	var mismatch *Error
	for key, pos := range locations {
		if key != strings.ToLower(key) && (mismatch == nil || pos.line < mismatch.Line || pos.line == mismatch.Line && pos.column < mismatch.Column) {
			mismatch = &Error{Filename: filename, Key: key, Line: pos.line, Column: pos.column, Err: errors.New("unknown key; schema keys are case-sensitive")}
		}
	}
	if mismatch != nil {
		return Config{}, mismatch
	}
	if err := cfg.Validate(); err != nil {
		key, message, ok := strings.Cut(err.Error(), ": ")
		if !ok {
			key, message = "", err.Error()
		}
		position := locations[key]
		// A required child can be absent. Point to its nearest explicit table rather
		// than inventing a line for a nonexistent key.
		for parent := key; position.line == 0; {
			i := strings.LastIndexByte(parent, '.')
			if i < 0 {
				break
			}
			parent = parent[:i]
			position = locations[parent]
		}
		return Config{}, &Error{Filename: filename, Key: key, Line: position.line, Column: position.column, Err: errors.New(message)}
	}
	return cfg, nil
}

func decodeError(filename string, err error) error {
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		diagnostics := make([]error, 0, len(strict.Errors))
		for i := range strict.Errors {
			diagnostics = append(diagnostics, locatedDecodeError(filename, &strict.Errors[i]))
		}
		return errors.Join(diagnostics...)
	}
	var syntax *toml.DecodeError
	if errors.As(err, &syntax) {
		return locatedDecodeError(filename, syntax)
	}
	return &Error{Filename: filename, Err: err}
}

func locatedDecodeError(filename string, err *toml.DecodeError) error {
	line, column := err.Position()
	return &Error{Filename: filename, Key: strings.Join(err.Key(), "."), Line: line, Column: column, Err: err}
}

type sourcePosition struct{ line, column int }

// Keep the pinned library's AST dependency confined to source location lookup.
// Parsing/typing/unknown-field rejection use its stable Decoder API above.
func sourceLocations(data []byte) map[string]sourcePosition {
	positions := make(map[string]sourcePosition)
	var parser unstable.Parser
	parser.Reset(data)
	keyParts := func(node *unstable.Node) ([]string, sourcePosition) {
		var parts []string
		var pos sourcePosition
		it := node.Key()
		for it.Next() {
			if len(parts) == 0 {
				start := parser.Shape(it.Node().Raw).Start
				pos = sourcePosition{start.Line, start.Column}
			}
			parts = append(parts, string(it.Node().Data))
		}
		return parts, pos
	}
	var visit func(*unstable.Node, []string)
	visit = func(node *unstable.Node, base []string) {
		parts, pos := keyParts(node)
		key := append(append([]string(nil), base...), parts...)
		positions[strings.Join(key, ".")] = pos
		value := node.Value()
		if value.Kind == unstable.InlineTable {
			children := value.Children()
			for children.Next() {
				visit(children.Node(), key)
			}
		}
	}
	var table []string
	for parser.NextExpression() {
		node := parser.Expression()
		switch node.Kind {
		case unstable.Table, unstable.ArrayTable:
			var pos sourcePosition
			table, pos = keyParts(node)
			positions[strings.Join(table, ".")] = pos
		case unstable.KeyValue:
			visit(node, table)
		}
	}
	return positions
}

// Load reads an existing file without creating or rewriting anything. Missing
// and malformed files return errors; callers decide how to present Defaults.
func Load(path string) (Config, error) {
	absolute, err := absoluteConfigPath(path)
	if err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return Config{}, fmt.Errorf("load config %s: %w", absolute, err)
	}
	cfg, err := Decode(data, absolute)
	if err != nil {
		return Config{}, err
	}
	return ResolvePaths(cfg, absolute)
}
