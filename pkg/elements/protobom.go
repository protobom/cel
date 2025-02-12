// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package elements

import (
	"errors"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

var (
	ProtobomObject = decls.NewObjectType("protobom")
	ProtobomType   = cel.ObjectType("protobom", traits.ReceiverType)
)

// Protobom is a global object that the CEL integration exposes in the environment
// this object groups some of the SBOM utility functions that are not methods
// of the protobom elements.
type Protobom struct{}

func (*Protobom) ConvertToNative(reflect.Type) (any, error) {
	return nil, errors.New("protobom objects cannot be converted to native")
}

// ConvertToType implements ref.Val.ConvertToType.
func (*Protobom) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.TypeType:
		return ProtobomType
	default:
		return types.NewErr("type conversion not allowed for protobom")
	}
}

// Equal implements ref.Val.Equal.
func (*Protobom) Equal(ref.Val) ref.Val {
	return types.True
}

func (*Protobom) Type() ref.Type {
	return ProtobomType
}

// Value implements ref.Val.Value.
func (p *Protobom) Value() any {
	return p
}
