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

var MetadataType = cel.ObjectType("protobom.protobom.Metadata")

type Metadata struct {
	*sbom.Metadata
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (md *Metadata) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(md).AssignableTo(typeDesc) {
		return md, nil
	} else if reflect.TypeOf(md.Metadata).AssignableTo(typeDesc) {
		return md.Metadata, nil
	}

	return nil, fmt.Errorf("type conversion error from 'Metadata' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (md *Metadata) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case MetadataType:
		return md
		// TODO(puerco): Add sbom.Doc type conversion
	case types.TypeType:
		return MetadataType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", MetadataType, typeVal)
}

// Equal implements ref.Val.Equal.
func (*Metadata) Equal(other ref.Val) ref.Val {
	// This cannot be implemented yet until the protobom Document supports
	// comparison
	return types.MaybeNoSuchOverloadErr(other)
}

func (*Metadata) Type() ref.Type {
	return MetadataType
}

// Value implements ref.Val.Value.
func (md *Metadata) Value() any {
	return md.Metadata
}

var _ traits.Indexer = (*Document)(nil)

func (md *Metadata) Get(index ref.Val) ref.Val {
	switch v := index.Value().(type) {
	case string:
		switch v {
		case "id":
			return types.String(md.Id)
		case propName:
			return types.String(md.Name)
		case propVersion:
			return types.String(md.Version)
		case "tools":
			toolsList := make([]ref.Val, len(md.Tools))
			for i, t := range md.Tools {
				toolsList[i] = &Tool{
					Tool: t,
				}
			}
			return types.NewRefValList(types.DefaultTypeAdapter, toolsList)
		case "authors":
			authorsList := make([]ref.Val, len(md.Authors))
			for i, p := range md.Authors {
				authorsList[i] = &Person{
					Person: p,
				}
			}
			return types.NewRefValList(types.DefaultTypeAdapter, authorsList)
		case "date":
			return types.Timestamp{Time: md.Date.AsTime()}
		case propComment:
			return types.String(md.Comment)
		case "source_data":
			return &SourceData{
				SourceData: md.SourceData,
			}
		default:
			return types.NewErr("no such key %v", index)
		}

	default:
		return types.NewErr("no such key %v", index)
	}
}
