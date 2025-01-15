// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package shell

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/protobom/cel/pkg/library"
	// "github.com/google/cel-go/common/operators"
	// "github.com/google/cel-go/common/types/traits"
	// celfuncs "github.com/google/cel-go/interpreter/functions"
)

func createEnvironment(opts *Options) (*cel.Env, error) {
	envOpts := []cel.EnvOption{
		library.NewProtobom().EnvOption(),
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),
	}

	// Add any additional environment options passed in the construcutor
	envOpts = append(envOpts, opts.EnvOptions...)
	env, err := cel.NewEnv(
		envOpts...,
	)
	if err != nil {
		return nil, (fmt.Errorf("creating CEL environment: %w", err))
	}

	return env, nil
}
