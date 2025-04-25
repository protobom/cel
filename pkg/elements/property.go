// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package elements

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/protobom/protobom/pkg/sbom"
)

var PropertyType = cel.ObjectType("protobom.protobom.Property")

type Property struct {
	*sbom.Property
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (p *Property) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(p).AssignableTo(typeDesc) {
		return p, nil
	} else if reflect.TypeOf(p.Property).AssignableTo(typeDesc) {
		return p.Property, nil
	}

	return nil, fmt.Errorf("type conversion error from 'Property' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (p *Property) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case PropertyType:
		return p
	case types.TypeType:
		return DocumentType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", PropertyType, typeVal)
}

// Equal implements ref.Val.Equal.
func (p *Property) Equal(other ref.Val) ref.Val {
	return types.MaybeNoSuchOverloadErr(other)
}

func (*Property) Type() ref.Type {
	return PropertyType
}

// Value implements ref.Val.Value.
func (p *Property) Value() any {
	return p.Property
}

var _ traits.Indexer = (*Property)(nil)

// Get is the getter to implement the indexer trait
func (p *Property) Get(index ref.Val) ref.Val {
	switch v := index.Value().(type) {
	case string:
		switch v {
		case "name":
			return types.String(p.Name)
		case "data":
			return types.String(p.Data)
		default:
			return types.NewErr("no such key %v", index)
		}

	default:
		return types.NewErr("no such key %v", index)
	}
}
