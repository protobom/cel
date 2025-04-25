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

var EdgeType = cel.ObjectType("protobom.protobom.Edge")

type Edge struct {
	*sbom.Edge
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (e *Edge) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(e).AssignableTo(typeDesc) {
		return e, nil
	} else if reflect.TypeOf(e.Edge).AssignableTo(typeDesc) {
		return e.Edge, nil
	}

	return nil, fmt.Errorf("type conversion error from 'Edge' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (e *Edge) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case EdgeType:
		return e
		// TODO(puerco): Add sbom.Doc type conversion
	case types.TypeType:
		return DocumentType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", EdgeType, typeVal)
}

// Equal implements ref.Val.Equal.
func (e *Edge) Equal(other ref.Val) ref.Val {
	// TODO(puerco): Implement with e.Edge.Equal()
	return types.MaybeNoSuchOverloadErr(other)
}

func (*Edge) Type() ref.Type {
	return EdgeType
}

// Value implements ref.Val.Value.
func (e *Edge) Value() any {
	return e.Edge
}

var _ traits.Indexer = (*Edge)(nil)

// Get is the getter to implement the indexer trait
func (e *Edge) Get(index ref.Val) ref.Val {
	switch v := index.Value().(type) {
	case string:
		switch v {
		case propType:
			if _, ok := sbom.Edge_Type_name[int32(e.GetType())]; ok {
				return types.String(sbom.Edge_Type_name[int32(e.GetType())])
			}
			return types.String(sbom.Edge_Type_name[0])
		case "from":
			return types.String(e.From)
		case "to":
			return types.NewDynamicList(types.DefaultTypeAdapter, e.To)
		default:
			return types.NewErr("no such key %v", index)
		}

	default:
		return types.NewErr("no such key %v", index)
	}
}
