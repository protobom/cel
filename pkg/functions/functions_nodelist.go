// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package functions

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/protobom/cel/pkg/adapter"
	"github.com/protobom/cel/pkg/elements"
	"github.com/protobom/protobom/pkg/sbom"
)

func NodeDescendants(vals ...ref.Val) ref.Val {
	if len(vals) != 3 {
		return types.NewErr("incorrect number of params")
	}
	nl, ok := vals[0].Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("first arg must me a nodelist")
	}
	id, ok := vals[1].Value().(string)
	if !ok {
		return types.NewErr("node id must be a string, not %T", vals[1].Value())
	}
	maxDepth, ok := vals[2].Value().(int64)
	if !ok {
		return types.NewErr("maxDepth must be an int, not %T", vals[2].Value())
	}
	return &elements.NodeList{NodeList: nl.NodeDescendants(id, int(maxDepth))}
}

// GetNodesByName takes a name and returns a list of nodes matching it
func GetNodesByName(lhs, rhs ref.Val) ref.Val {
	name, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("name must be a string")
	}
	switch v := lhs.Value().(type) {
	case *sbom.NodeList:
		l := []ref.Val{}
		for _, n := range v.GetNodesByName(name) {
			l = append(l, &elements.Node{
				Node: n,
			})
		}
		return types.NewRefValList(adapter.ProtobomTypeAdapter{}, l)
	default:
		return types.NewErr("no mathcing overload for GetNodesByName on %T", v)
	}
}

var NodesByPurlType = func(lhs, rhs ref.Val) ref.Val {
	purlType, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("argument to GetNodesByPurlType must be a string")
	}

	var nl *sbom.NodeList
	switch v := lhs.Value().(type) {
	case *sbom.Document:
		nl = v.NodeList.GetNodesByPurlType(purlType)
	case *sbom.NodeList:
		nl = v.GetNodesByPurlType(purlType)
	default:
		return types.NewErr("method unsupported on type %T", lhs.Value())
	}

	return &elements.NodeList{
		NodeList: nl,
	}
}
