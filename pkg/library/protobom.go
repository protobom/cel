// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

// Package library defined CEL compile and program options in an object that can
// be used as a library in a CEL environment.
package library

import (
	"slices"

	"github.com/google/cel-go/cel"
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/protobom/cel/pkg/adapter"
	"github.com/protobom/cel/pkg/elements"
)

const (
	Name = "cel.protobom.api"
)

type Protobom struct{}

func NewProtobom() *Protobom {
	return &Protobom{}
}

// Types returns the types that the library defines in the CEL environment
func (*Protobom) Types() []cel.EnvOption {
	// Extract the protobom descriptor to pass to the engine
	messageType := (&sbom.Document{}).ProtoReflect().Type()
	descriptor := messageType.Descriptor().ParentFile()

	return []cel.EnvOption{
		cel.TypeDescs(
			descriptor,
		),
		cel.Types(elements.DocumentType),
		cel.Types(elements.MetadataType),
		cel.Types(elements.PersonType),
		cel.Types(&sbom.Document{}),
		cel.Types(&sbom.NodeList{}),
		cel.Types(&sbom.Node{}),
		cel.Types(&sbom.Person{}),
		cel.Types(&sbom.Metadata{}),
	}
}

// Variables defines the global variables that are created in the CEL
// environment when the library is included
func (*Protobom) Variables() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("sboms", cel.MapType(cel.IntType, elements.DocumentType)),
		cel.Variable("docs", cel.MapType(cel.IntType, cel.DynType)),
		cel.Variable("protobom", elements.ProtobomType),
	}
}

// TypeAdapters wraps the protobom custom type adapter into an option
// that can be injected into the CEL environment
func (*Protobom) TypeAdapters() []cel.EnvOption {
	return []cel.EnvOption{
		cel.CustomTypeAdapter(&adapter.ProtobomTypeAdapter{}),
	}
}

// CompileOptions creates the CEL execution environment that the runner will
// use to compile and evaluate programs on the SBOM
func (p *Protobom) CompileOptions() []cel.EnvOption {
	return slices.Concat(
		p.Types(),
		p.Variables(),
		p.Functions(),
		p.TypeAdapters(),
	)
}

// ProgramOptions is here to implement the cel library interface, currently
// none are supported.
func (*Protobom) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// LibraryName returns the library name as defined in the Name constant
func (*Protobom) LibraryName() string {
	return Name
}

// EnvOption compiles the library and supporting functions into
// a CEL library that can be added to a CEL environment.
func (p *Protobom) EnvOption() cel.EnvOption {
	return cel.Lib(p)
}
