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

var (
	NodeObject = decls.NewObjectType("protobom.protobom.Node")
	NodeType   = cel.ObjectType("protobom.protobom.Node")
)

type Node struct {
	*sbom.Node
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (n *Node) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(n).AssignableTo(typeDesc) {
		return n, nil
	} else if reflect.TypeOf(n.Node).AssignableTo(typeDesc) {
		return n.Node, nil
	}

	return nil, fmt.Errorf("type conversion error from 'Node' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (n *Node) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case NodeType:
		return n
	case types.TypeType:
		return NodeType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", NodeType, typeVal)
}

// Equal implements ref.Val.Equal.
func (n *Node) Equal(other ref.Val) ref.Val {
	otherNode, ok := other.(*Node)
	if !ok {
		return types.MaybeNoSuchOverloadErr(other)
	}

	if n.Node.Equal(otherNode.Node) {
		return types.True
	}
	return types.False
}

func (*Node) Type() ref.Type {
	return NodeType
}

// Value implements ref.Val.Value.
func (n *Node) Value() any {
	return n.Node
}

// ToNodeList returns a new NodeList with the node as the only member
func (n *Node) ToNodeList() *NodeList {
	return &NodeList{
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{n.Node},
			Edges:        []*sbom.Edge{},
			RootElements: []string{n.Id},
		},
	}
}
