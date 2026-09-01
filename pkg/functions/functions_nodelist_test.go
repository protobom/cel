// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors

package functions

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/traits"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"github.com/protobom/cel/pkg/elements"
)

const (
	rootNodeID = "root"
	midNodeID  = "mid"
)

// testGraphNodeList builds the chain root -> mid -> leaf the graph function
// tests operate on.
func testGraphNodeList() *elements.NodeList {
	return &elements.NodeList{
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{Id: rootNodeID}, {Id: midNodeID}, {Id: "leaf"},
			},
			Edges: []*sbom.Edge{
				{Type: sbom.Edge_contains, From: rootNodeID, To: []string{midNodeID}},
				{Type: sbom.Edge_dependsOn, From: midNodeID, To: []string{"leaf"}},
			},
			RootElements: []string{"root"},
		},
	}
}

func TestFunctionNodeAncestors(t *testing.T) {
	res := NodeAncestors(testGraphNodeList(), types.String("leaf"), types.Int(10))
	nl, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, nl.Nodes, 3, "the whole chain above the leaf comes back")

	res = NodeAncestors(testGraphNodeList(), types.String("leaf"), types.Int(1))
	nl, ok = res.Value().(*sbom.NodeList)
	require.True(t, ok)
	require.Len(t, nl.Nodes, 2, "one level up returns the direct parent")

	res = NodeAncestors(testGraphNodeList(), types.String("leaf"))
	require.True(t, types.IsError(res), "missing arguments must error")
}

func TestFunctionGetEdgesFrom(t *testing.T) {
	res := GetEdgesFrom(testGraphNodeList(), types.String(rootNodeID))
	require.False(t, types.IsError(res), "%v", res)
	lister, ok := res.(traits.Lister)
	require.True(t, ok)
	require.Equal(t, types.Int(1), lister.Size())

	res = GetEdgesFrom(testGraphNodeList(), types.String("leaf"))
	lister, ok = res.(traits.Lister)
	require.True(t, ok)
	require.Equal(t, types.Int(0), lister.Size())
}

func TestFunctionGetEdgesTo(t *testing.T) {
	res := GetEdgesTo(testGraphNodeList(), types.String("leaf"))
	require.False(t, types.IsError(res), "%v", res)
	lister, ok := res.(traits.Lister)
	require.True(t, ok)
	require.Equal(t, types.Int(1), lister.Size())

	res = GetEdgesTo(testGraphNodeList(), types.String(rootNodeID))
	lister, ok = res.(traits.Lister)
	require.True(t, ok)
	require.Equal(t, types.Int(0), lister.Size())
}

func TestFunctionUnrelateNodes(t *testing.T) {
	sut := testGraphNodeList()
	res := UnrelateNodes(sut, types.String(midNodeID), types.String("leaf"), types.String("dependsOn"))
	nl, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, nl.Edges, 1, "the dependsOn edge is gone")
	require.Equal(t, sbom.Edge_contains, nl.Edges[0].Type)

	require.Len(t, sut.Edges, 2, "the original nodelist is not modified")

	res = UnrelateNodes(sut, types.String(midNodeID), types.String("leaf"), types.String("not-a-type"))
	require.True(t, types.IsError(res), "an unknown relationship type must error")
}

func TestFunctionRemoveEdgesFrom(t *testing.T) {
	sut := testGraphNodeList()
	res := RemoveEdgesFrom(sut, types.String(rootNodeID), types.String("contains"))
	nl, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, nl.Edges, 1)
	require.Equal(t, sbom.Edge_dependsOn, nl.Edges[0].Type)

	require.Len(t, sut.Edges, 2, "the original nodelist is not modified")

	res = RemoveEdgesFrom(sut, types.String(rootNodeID), types.String("not-a-type"))
	require.True(t, types.IsError(res), "an unknown relationship type must error")
}
