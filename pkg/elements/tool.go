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

var ToolType = cel.ObjectType("protobom.protobom.Tool")

type Tool struct {
	*sbom.Tool
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (t *Tool) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(t).AssignableTo(typeDesc) {
		return t, nil
	} else if reflect.TypeOf(t.Tool).AssignableTo(typeDesc) {
		return t.Tool, nil
	}

	return nil, fmt.Errorf("type conversion error from '%s' to '%v'", ToolType, typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (t *Tool) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case ToolType:
		return t
	case types.TypeType:
		return ToolType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", ToolType, typeVal)
}

// Equal implements ref.Val.Equal.
func (t *Tool) Equal(other ref.Val) ref.Val {
	return types.MaybeNoSuchOverloadErr(other)
}

func (*Tool) Type() ref.Type {
	return ToolType
}

// Value implements ref.Val.Value.
func (t *Tool) Value() any {
	return t.Tool
}

var _ traits.Indexer = (*Tool)(nil)

// Get is the getter to implement the indexer trait
func (t *Tool) Get(index ref.Val) ref.Val {
	switch v := index.Value().(type) {
	case string:
		switch v {
		case propName:
			return types.String(t.Name)
		case propVersion:
			return types.String(t.Version)
		case "vendor":
			return types.String(t.Vendor)
		default:
			return types.NewErr("no such key %v", index)
		}

	default:
		return types.NewErr("no such key %v", index)
	}
}
