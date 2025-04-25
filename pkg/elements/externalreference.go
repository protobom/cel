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

var ExternalReferenceType = cel.ObjectType("protobom.protobom.ExternalReference")

type ExternalReference struct {
	*sbom.ExternalReference
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (er *ExternalReference) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(er).AssignableTo(typeDesc) {
		return er, nil
	} else if reflect.TypeOf(er.ExternalReference).AssignableTo(typeDesc) {
		return er.ExternalReference, nil
	}

	return nil, fmt.Errorf("type conversion error from 'ExternalReference' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (er *ExternalReference) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case ExternalReferenceType:
		return er
	case types.TypeType:
		return DocumentType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", ExternalReferenceType, typeVal)
}

// Equal implements ref.Val.Equal.
func (er *ExternalReference) Equal(other ref.Val) ref.Val {
	// TODO(puerco): Implement with e.Edge.Equal()
	return types.MaybeNoSuchOverloadErr(other)
}

func (*ExternalReference) Type() ref.Type {
	return ExternalReferenceType
}

// Value implements ref.Val.Value.
func (er *ExternalReference) Value() any {
	return er.ExternalReference
}

var _ traits.Indexer = (*ExternalReference)(nil)

// Get is the getter to implement the indexer trait
func (er *ExternalReference) Get(index ref.Val) ref.Val {
	switch v := index.Value().(type) {
	case string:
		switch v {
		case propType:
			if _, ok := sbom.Edge_Type_name[int32(er.GetType())]; ok {
				return types.String(sbom.ExternalReference_ExternalReferenceType_name[int32(er.GetType())])
			}
			return types.String(sbom.ExternalReference_ExternalReferenceType_name[0])
		case "url":
			return types.String(er.Url)
		case propComment:
			return types.String(er.Comment)
		case "authority":
			return types.String(er.Authority)
		case propHashes:
			ret := map[string]string{}
			for a, v := range er.Hashes {
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
