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

var DocumentType = cel.ObjectType("protobom.protobom.Document")

type Document struct {
	*sbom.Document
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (d *Document) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(d).AssignableTo(typeDesc) {
		return d, nil
	} else if reflect.TypeOf(d.Document).AssignableTo(typeDesc) {
		return d.Document, nil
	}

	return nil, fmt.Errorf("type conversion error from 'Document' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (d *Document) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case DocumentType:
		return d
		// TODO(puerco): Add sbom.Doc type conversion
	case types.TypeType:
		return DocumentType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", DocumentType, typeVal)
}

// Equal implements ref.Val.Equal.
func (*Document) Equal(other ref.Val) ref.Val {
	// This cannot be implemented yet until the protobom Document supports
	// comparison
	return types.MaybeNoSuchOverloadErr(other)
}

func (*Document) Type() ref.Type {
	return DocumentType
}

// Value implements ref.Val.Value.
func (d *Document) Value() any {
	return d.Document
}

var _ traits.Indexer = (*Document)(nil)

func (d *Document) Get(index ref.Val) ref.Val {
	switch v := index.Value().(type) {
	case string:
		switch v {
		case "nodelist":
			return &NodeList{
				NodeList: d.NodeList,
			}
		default:
			return types.NewErr("no such key %v", index)
		}

	default:
		return types.NewErr("no such key %v", index)
	}
}
