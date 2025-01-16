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
	NodeListObject = decls.NewObjectType("protobom.protobom.NodeList")
	NodeListType   = cel.ObjectType("protobom.protobom.NodeList")
)

type NodeList struct {
	*sbom.NodeList
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (nl NodeList) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(nl).AssignableTo(typeDesc) {
		return nl, nil
	} else if reflect.TypeOf(nl.NodeList).AssignableTo(typeDesc) {
		return nl.NodeList, nil
	}
	return nil, fmt.Errorf("type conversion error from 'NodeList' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (nl NodeList) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case NodeListType:
		return nl
	case types.TypeType:
		return NodeListType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", NodeListType, typeVal)
}

// Equal implements ref.Val.Equal.
func (nl NodeList) Equal(other ref.Val) ref.Val {
	otherNodeList, ok := other.(NodeList)
	if !ok {
		return types.MaybeNoSuchOverloadErr(other)
	}

	if nl.NodeList.Equal(otherNodeList.NodeList) {
		return types.True
	}
	return types.False
}

// Type implements ref.Val.Type.
func (nl NodeList) Type() ref.Type {
	return NodeListType
}

// Value implements ref.Val.Value.
func (nl NodeList) Value() any {
	return nl.NodeList
}

// Add should at least merge two nodelists together.
func (nl NodeList) Add(incoming ref.Val) {
	newNodeList, ok := incoming.(NodeList)
	if !ok {
		// Here we should have a method to err
		return
	}

	for _, n := range newNodeList.Nodes {
		if !nl.HasNodeWithID(n.Id) {
			nl.Nodes = append(nl.Nodes, n)
		}
	}

	for _, e := range newNodeList.Edges {
		nl.AddEdge(e.From, e.Type, e.To)
	}
}

// AddEsge adds edge data to
func (nl NodeList) AddEdge(from string, t sbom.Edge_Type, to []string) {
	for i := range nl.Edges {
		// If there is already an edge with the same data, just add
		if nl.Edges[i].From == from && nl.Edges[i].Type == t {
			for _, newTo := range to {
				add := true
				for _, existingTo := range nl.Edges[i].To {
					if existingTo == newTo {
						add = false
						break
					}
				}
				if !add {
					continue
				}
				nl.Edges[i].To = append(nl.Edges[i].To, newTo)
			}
			return
		}
	}
	// .. otherwise add a new edge
	nl.Edges = append(nl.Edges, &sbom.Edge{
		Type: t,
		From: from,
		To:   to,
	})
}

// HasNodeWithID Returns true if the NodeList already has a node with the specified ID
func (nl NodeList) HasNodeWithID(nodeID string) bool {
	for _, n := range nl.Nodes {
		if n.Id == nodeID {
			return true
		}
	}
	return false
}
