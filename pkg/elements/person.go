// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package elements

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/protobom/protobom/pkg/sbom"
)

type Person struct {
	*sbom.Person
}

var (
	PersonObject = decls.NewObjectType("protobom.protobom.Person")
	PersonType   = cel.ObjectType("protobom.protobom.Person")
)

func (p *Person) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(p).AssignableTo(typeDesc) {
		return p, nil
	} else if reflect.TypeOf(p.Person).AssignableTo(typeDesc) {
		return p.Person, nil
	}

	return nil, fmt.Errorf("type conversion error from 'Person' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (p *Person) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case PersonType:
		return p
	case types.TypeType:
		return PersonType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", NodeType, typeVal)
}

func (p *Person) Equal(other ref.Val) ref.Val {
	// Not yet implemented
	return types.False
}

func (*Person) Type() ref.Type {
	return PersonType
}

// Value implements ref.Val.Value.
func (p *Person) Value() any {
	return p.Person
}
