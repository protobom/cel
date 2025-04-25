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
	"github.com/google/cel-go/common/types/traits"
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

var _ traits.Indexer = (*Person)(nil)

// Get is the getter to implement the indexer trait
func (p *Person) Get(index ref.Val) ref.Val {
	switch v := index.Value().(type) {
	case string:
		switch v {
		case propName:
			return types.String(p.GetName())
		case "is_org":
			return types.Bool(p.GetIsOrg())
		case "email":
			return types.String(p.GetEmail())
		case "phone":
			return types.String(p.GetPhone())
		case "contacts":
			personsList := []ref.Val{}
			if p.GetContacts() != nil {
				for _, person := range p.GetContacts() {
					p := &Person{
						Person: person,
					}
					personsList = append(personsList, p)
				}
			}
			return types.NewRefValList(types.DefaultTypeAdapter, personsList)
		default:
			return types.NewErr("no such key %v", index)
		}

	default:
		return types.NewErr("no such key %v", index)
	}
}
