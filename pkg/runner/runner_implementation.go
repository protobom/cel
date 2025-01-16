// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package runner

import (
	"fmt"
	"io"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
)

type Implementation interface {
	ReadStream(io.Reader) (string, error)
	Compile(*cel.Env, string) (*cel.Ast, error)
	Evaluate(*cel.Env, *cel.Ast, map[string]any) (ref.Val, error)
}

type defaultRunnerImplementation struct{}

func (dri *defaultRunnerImplementation) ReadStream(reader io.Reader) (string, error) {
	// Read all the stream into a string
	contents, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("reading stram code: %w", err)
	}
	return string(contents), nil
}

// Compile reads CEL code from string, compiles it and
// returns the Abstract Syntax Tree (AST). The AST can then be evaluated
// in the environment. As compilation of the AST is expensive, it can
// be cached for better performance.
func (dri *defaultRunnerImplementation) Compile(env *cel.Env, code string) (*cel.Ast, error) {
	// Run the compilation step
	ast, iss := env.Compile(code)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compilation error: %w", iss.Err())
	}
	return ast, nil
}

// EvaluateAST evaluates a CEL syntax tree on an SBOM. Returns the program
// evaluation result or an error.
func (dri *defaultRunnerImplementation) Evaluate(env *cel.Env, ast *cel.Ast, variables map[string]any) (ref.Val, error) {
	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("generating program from AST: %w", err)
	}

	// Run the evaluation
	result, _, err := program.Eval(variables)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	return result, nil
}
