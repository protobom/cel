// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package library

// Options groups the knobs that can be flicked to control how the
// library behaves when embedding it into a CEL environment
type Options struct {
	// EnableIO enables the functions that call to the network or the
	// local filesystem. If false, these functions will not be available
	// in the CEL runtime.
	EnableIO bool

	// ProtobomVarName is the name of the global variable of the protobom
	// object that hosts all the protobom.* functions
	ProtobomVarName string

	// DocsVarName is the name of the variable that holds the loaded SBOMs.
	DocsVarName string
}

var DefaultOptions = Options{
	EnableIO:        false,
	ProtobomVarName: "protobom",
	DocsVarName:     "sboms",
}

type OptFunc func(*Options)

func WithEnableIO(w bool) OptFunc {
	return func(o *Options) {
		o.EnableIO = w
	}
}

func WithProtobomVarName(name string) OptFunc {
	return func(o *Options) {
		o.ProtobomVarName = name
	}
}

func WithDocsVarName(name string) OptFunc {
	return func(o *Options) {
		o.DocsVarName = name
	}
}
