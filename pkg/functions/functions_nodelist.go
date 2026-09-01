// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package functions

import (
	"fmt"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/protobom/cel/pkg/adapter"
	"github.com/protobom/cel/pkg/elements"
)

// edgeTypeFromString resolves the name of a protobom relationship type.
func edgeTypeFromString(name string) (sbom.Edge_Type, error) {
	if v, ok := sbom.Edge_Type_value[name]; ok {
		return sbom.Edge_Type(v), nil
	}
	return sbom.Edge_UNKNOWN, fmt.Errorf("unknown relationship type %q", name)
}

// NodeAncestors returns the nodelist fragment with the elements pointing to
// a node, walking the graph in the inverse direction of NodeDescendants.
func NodeAncestors(vals ...ref.Val) ref.Val {
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
	return &elements.NodeList{NodeList: nl.NodeAncestors(id, int(maxDepth))}
}

// GetEdgesFrom returns the edges originating at a node.
var GetEdgesFrom = func(lhs, rhs ref.Val) ref.Val {
	id, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("node id must be a string")
	}
	nl, ok := lhs.Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("get_edges_from only applies to NodeList")
	}
	edges := nl.GetEdgesFrom(id)
	l := make([]ref.Val, 0, len(edges))
	for _, e := range edges {
		l = append(l, &elements.Edge{Edge: e})
	}
	return types.NewRefValList(adapter.ProtobomTypeAdapter{}, l)
}

// GetEdgesTo returns the edges pointing to a node.
var GetEdgesTo = func(lhs, rhs ref.Val) ref.Val {
	id, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("node id must be a string")
	}
	nl, ok := lhs.Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("get_edges_to only applies to NodeList")
	}
	edges := nl.GetEdgesTo(id)
	l := make([]ref.Val, 0, len(edges))
	for _, e := range edges {
		l = append(l, &elements.Edge{Edge: e})
	}
	return types.NewRefValList(adapter.ProtobomTypeAdapter{}, l)
}

// UnrelateNodes returns a new nodelist with the relationship of the given
// type between two nodes removed. The nodelist the function is invoked on is
// not modified.
func UnrelateNodes(vals ...ref.Val) ref.Val {
	if len(vals) != 4 {
		return types.NewErr("incorrect number of params")
	}
	nl, ok := vals[0].Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("unrelate_nodes only applies to NodeList")
	}
	from, ok := vals[1].Value().(string)
	if !ok {
		return types.NewErr("node id must be a string, not %T", vals[1].Value())
	}
	to, ok := vals[2].Value().(string)
	if !ok {
		return types.NewErr("node id must be a string, not %T", vals[2].Value())
	}
	typeName, ok := vals[3].Value().(string)
	if !ok {
		return types.NewErr("relationship type must be a string, not %T", vals[3].Value())
	}
	edgeType, err := edgeTypeFromString(typeName)
	if err != nil {
		return types.NewErr("%v", err)
	}

	ret := nl.Copy()
	ret.UnrelateNodes(from, to, edgeType)
	return &elements.NodeList{NodeList: ret}
}

// RemoveEdgesFrom returns a new nodelist without the edges of the given type
// originating at a node. The nodelist the function is invoked on is not
// modified.
func RemoveEdgesFrom(vals ...ref.Val) ref.Val {
	if len(vals) != 3 {
		return types.NewErr("incorrect number of params")
	}
	nl, ok := vals[0].Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("remove_edges_from only applies to NodeList")
	}
	from, ok := vals[1].Value().(string)
	if !ok {
		return types.NewErr("node id must be a string, not %T", vals[1].Value())
	}
	typeName, ok := vals[2].Value().(string)
	if !ok {
		return types.NewErr("relationship type must be a string, not %T", vals[2].Value())
	}
	edgeType, err := edgeTypeFromString(typeName)
	if err != nil {
		return types.NewErr("%v", err)
	}

	ret := nl.Copy()
	ret.RemoveEdgesFrom(from, edgeType)
	return &elements.NodeList{NodeList: ret}
}

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

// Intersect returns a new nodelist with the nodes and relationships common
// to both operands.
var Intersect = func(lhs, rhs ref.Val) ref.Val {
	nl1, ok := lhs.Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("intersect only applies to a nodelist, not %T", lhs.Value())
	}
	nl2, ok := rhs.Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("only a nodelist can be intersected with a nodelist, not %T", rhs.Value())
	}
	return &elements.NodeList{
		NodeList: nl1.Intersect(nl2),
	}
}

// NodeGraph returns the full graph of the node with the given ID.
var NodeGraph = func(lhs, rhs ref.Val) ref.Val {
	id, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("node id must be a string")
	}
	nl, ok := lhs.Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("get_node_graph only applies to NodeList")
	}
	graph := nl.NodeGraph(id)
	if graph == nil {
		graph = &sbom.NodeList{}
	}
	return &elements.NodeList{NodeList: graph}
}

// NodeSiblings returns the fragment with the immediate siblings of the node
// with the given ID.
var NodeSiblings = func(lhs, rhs ref.Val) ref.Val {
	id, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("node id must be a string")
	}
	nl, ok := lhs.Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("get_node_siblings only applies to NodeList")
	}
	siblings := nl.NodeSiblings(id)
	if siblings == nil {
		siblings = &sbom.NodeList{}
	}
	return &elements.NodeList{NodeList: siblings}
}

// GetNodesByIdentifier returns the nodes carrying an identifier of the named
// type (such as "purl" or "cpe23") with the given value.
func GetNodesByIdentifier(vals ...ref.Val) ref.Val {
	if len(vals) != 3 {
		return types.NewErr("incorrect number of params")
	}
	nl, ok := vals[0].Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("get_nodes_by_identifier only applies to NodeList")
	}
	idType, ok := vals[1].Value().(string)
	if !ok {
		return types.NewErr("identifier type must be a string, not %T", vals[1].Value())
	}
	value, ok := vals[2].Value().(string)
	if !ok {
		return types.NewErr("identifier value must be a string, not %T", vals[2].Value())
	}

	nodes := nl.GetNodesByIdentifier(idType, value)
	l := make([]ref.Val, 0, len(nodes))
	for _, n := range nodes {
		l = append(l, &elements.Node{Node: n})
	}
	return types.NewRefValList(adapter.ProtobomTypeAdapter{}, l)
}

// GetMatchingNode looks up the node describing the same software as the
// provided node, matching by hashes and package URL. It evaluates to null
// when nothing matches and errors when more than one node does.
var GetMatchingNode = func(lhs, rhs ref.Val) ref.Val {
	nl, ok := lhs.Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("get_matching_node only applies to NodeList")
	}
	node, ok := rhs.Value().(*sbom.Node)
	if !ok {
		return types.NewErr("the argument to get_matching_node must be a node, not %T", rhs.Value())
	}

	match, err := nl.GetMatchingNode(node)
	if err != nil {
		return types.NewErr("matching node: %v", err)
	}
	if match == nil {
		return types.NullValue
	}
	return &elements.Node{Node: match}
}
