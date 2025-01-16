// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package runner

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"

	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/protobom/cel/pkg/elements"
	"github.com/protobom/cel/pkg/library"
)

type Options struct {
	EnvOptions []cel.EnvOption
}

var defaultOptions = Options{
	EnvOptions: []cel.EnvOption{
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),
	},
}

type Runner struct {
	Environment *cel.Env
	impl        RunnerImplementation
}

func NewRunner() (*Runner, error) {
	return NewRunnerWithOptions(&defaultOptions)
}

func NewRunnerWithOptions(opts *Options) (*Runner, error) {
	env, err := CreateEnvironment(opts)
	if err != nil {
		return nil, err
	}
	runner := Runner{
		Environment: env,
		impl:        &defaultRunnerImplementation{},
	}

	return &runner, nil
}

func (r *Runner) Evaluate(code string, variables *map[string]any) (ref.Val, error) {
	ast, err := r.impl.Compile(r.Environment, code)
	if err != nil {
		return nil, fmt.Errorf("compilation error: %w", err)
	}

	val, err := r.impl.Evaluate(r.Environment, ast, variables)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	return val, nil
}

// CreateEnvironment creates a CEL environment with the protobom
// library loaded.
func CreateEnvironment(opts *Options) (*cel.Env, error) {
	envOpts := []cel.EnvOption{
		library.NewProtobom().EnvOption(),
	}

	// Add any additional environment options defined in the options
	envOpts = append(envOpts, opts.EnvOptions...)

	// Create the CEL environment
	env, err := cel.NewEnv(
		envOpts...,
	)
	if err != nil {
		return nil, (fmt.Errorf("creating CEL environment: %w", err))
	}

	return env, nil
}

type varBuilderOptions struct {
	Paths     []string
	Documents []*sbom.Document
}

type varBuilderOption func(*varBuilderOptions)

func WithPaths(paths []string) varBuilderOption {
	return func(opts *varBuilderOptions) {
		opts.Paths = paths
	}
}

func WithDocuments(docs []*sbom.Document) varBuilderOption {
	return func(opts *varBuilderOptions) {
		opts.Documents = docs
	}
}

func BuildVariables(optsFn ...varBuilderOption) (*map[string]any, error) {
	opts := &varBuilderOptions{}
	for _, f := range optsFn {
		f(opts)
	}
	sbomList := []*elements.Document{}

	// Load the specified SBOM files
	r := reader.New()
	// Load defined SBOMs into the sboms array
	for _, path := range opts.Paths {
		doc, err := r.ParseFile(path)
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", path, err)
		}
		sbomList = append(sbomList, &elements.Document{
			Document: doc,
		})
	}

	// Add any preloaded documents to the list:
	for _, doc := range opts.Documents {
		sbomList = append(sbomList, &elements.Document{
			Document: doc,
		})
	}

	// Add the SBOM list to the runtim environment
	return &map[string]any{
		"protobom": elements.Protobom{},
		"sboms":    sbomList,
	}, nil

}
