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

type Protobom struct{}

func (p Protobom) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	return nil, errors.New("a protobom object cannot be converted to native")
}

// ConvertToType implements ref.Val.ConvertToType.
func (p *Protobom) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.TypeType:
		return ProtobomType
	default:
		return types.NewErr("type conversion not allowed for protobom")
	}
}

// Equal implements ref.Val.Equal.
func (p *Protobom) Equal(other ref.Val) ref.Val {
	return types.NewErr("protobom objects cannot be compared")
}

func (p *Protobom) Type() ref.Type {
	return ProtobomType
}

// Value implements ref.Val.Value.
func (p *Protobom) Value() interface{} {
	return p
}
