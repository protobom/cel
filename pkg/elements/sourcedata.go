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

var SourceDataType = cel.ObjectType("protobom.protobom.SourceData")

type SourceData struct {
	*sbom.SourceData
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (sd *SourceData) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(sd).AssignableTo(typeDesc) {
		return sd, nil
	} else if reflect.TypeOf(sd.SourceData).AssignableTo(typeDesc) {
		return sd.SourceData, nil
	}

	return nil, fmt.Errorf("type conversion error from '%s' to '%v'", SourceDataType, typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (sd *SourceData) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case SourceDataType:
		return sd
	case types.TypeType:
		return SourceDataType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", SourceDataType, typeVal)
}

// Equal implements ref.Val.Equal.
func (sd *SourceData) Equal(other ref.Val) ref.Val {
	return types.MaybeNoSuchOverloadErr(other)
}

func (*SourceData) Type() ref.Type {
	return SourceDataType
}

// Value implements ref.Val.Value.
func (sd *SourceData) Value() any {
	return sd.SourceData
}

var _ traits.Indexer = (*SourceData)(nil)

// Get is the getter to implement the indexer trait
func (sd *SourceData) Get(index ref.Val) ref.Val {
	switch v := index.Value().(type) {
	case string:
		switch v {
		case "format":
			return types.String(sd.Format)
		case "size":
			return types.Int(sd.Size)
		case "uri":
			if sd.Uri != nil {
				return types.String(*sd.Uri)
			}
			return types.String("")
		case propHashes:
			ret := map[string]string{}
			for a, v := range sd.Hashes {
				if _, ok := sbom.HashAlgorithm_name[a]; ok {
					ret[sbom.HashAlgorithm_name[a]] = v
				} else {
					ret[sbom.HashAlgorithm_name[0]] = v
				}
			}
			return types.NewDynamicMap(types.DefaultTypeAdapter, ret)
		default:
			return types.NewErr("no such key %v", index)
		}

	default:
		return types.NewErr("no such key %v", index)
	}
}
