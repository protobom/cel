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
	rootNodeID   = "root"
	midNodeID    = "mid"
	leafNodeID   = "leaf"
	containsName = "contains"
	incomingID   = "incoming"
)

// testGraphNodeList builds the chain root -> mid -> leaf the graph function
// tests operate on.
func testGraphNodeList() *elements.NodeList {
	return &elements.NodeList{
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{Id: rootNodeID}, {Id: midNodeID}, {Id: leafNodeID},
			},
			Edges: []*sbom.Edge{
				{Type: sbom.Edge_contains, From: rootNodeID, To: []string{midNodeID}},
				{Type: sbom.Edge_dependsOn, From: midNodeID, To: []string{leafNodeID}},
			},
			RootElements: []string{"root"},
		},
	}
}

func TestFunctionNodeAncestors(t *testing.T) {
	res := NodeAncestors(testGraphNodeList(), types.String(leafNodeID), types.Int(10))
	nl, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, nl.Nodes, 3, "the whole chain above the leaf comes back")

	res = NodeAncestors(testGraphNodeList(), types.String(leafNodeID), types.Int(1))
	nl, ok = res.Value().(*sbom.NodeList)
	require.True(t, ok)
	require.Len(t, nl.Nodes, 2, "one level up returns the direct parent")

	res = NodeAncestors(testGraphNodeList(), types.String(leafNodeID))
	require.True(t, types.IsError(res), "missing arguments must error")
}

func TestFunctionGetEdgesFrom(t *testing.T) {
	res := GetEdgesFrom(testGraphNodeList(), types.String(rootNodeID))
	require.False(t, types.IsError(res), "%v", res)
	lister, ok := res.(traits.Lister)
	require.True(t, ok)
	require.Equal(t, types.Int(1), lister.Size())

	res = GetEdgesFrom(testGraphNodeList(), types.String(leafNodeID))
	lister, ok = res.(traits.Lister)
	require.True(t, ok)
	require.Equal(t, types.Int(0), lister.Size())
}

func TestFunctionGetEdgesTo(t *testing.T) {
	res := GetEdgesTo(testGraphNodeList(), types.String(leafNodeID))
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
	res := UnrelateNodes(sut, types.String(midNodeID), types.String(leafNodeID), types.String("dependsOn"))
	nl, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, nl.Edges, 1, "the dependsOn edge is gone")
	require.Equal(t, sbom.Edge_contains, nl.Edges[0].Type)

	require.Len(t, sut.Edges, 2, "the original nodelist is not modified")

	res = UnrelateNodes(sut, types.String(midNodeID), types.String(leafNodeID), types.String("not-a-type"))
	require.True(t, types.IsError(res), "an unknown relationship type must error")
}

func TestFunctionRemoveEdgesFrom(t *testing.T) {
	sut := testGraphNodeList()
	res := RemoveEdgesFrom(sut, types.String(rootNodeID), types.String(containsName))
	nl, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, nl.Edges, 1)
	require.Equal(t, sbom.Edge_dependsOn, nl.Edges[0].Type)

	require.Len(t, sut.Edges, 2, "the original nodelist is not modified")

	res = RemoveEdgesFrom(sut, types.String(rootNodeID), types.String("not-a-type"))
	require.True(t, types.IsError(res), "an unknown relationship type must error")
}

func TestFunctionAddition(t *testing.T) {
	nl1 := testGraphNodeList()
	nl2 := &elements.NodeList{
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{{Id: leafNodeID}, {Id: "extra"}},
			Edges:        []*sbom.Edge{{Type: sbom.Edge_dependsOn, From: leafNodeID, To: []string{"extra"}}},
			RootElements: []string{},
		},
	}

	res := Addition(nl1, nl2)
	nl, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, nl.Nodes, 4, "the union combines the nodes of both lists")
	require.Len(t, nl.Edges, 3)
	require.Len(t, nl1.Nodes, 3, "the operands are not modified")
	require.Len(t, nl2.Nodes, 2, "the operands are not modified")

	res = Addition(nl1, types.String("not a nodelist"))
	require.True(t, types.IsError(res), "adding anything but a nodelist must error")

	res = AdditionOp(nl1, nl2)
	nl, ok = res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, nl.Nodes, 4)
}

func TestFunctionRelateNodeListAtID(t *testing.T) {
	incoming := &elements.NodeList{
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{{Id: incomingID}},
			Edges:        []*sbom.Edge{},
			RootElements: []string{incomingID},
		},
	}

	t.Run("on a nodelist", func(t *testing.T) {
		sut := testGraphNodeList()
		res := RelateNodeListAtID(sut, incoming, types.String(leafNodeID), types.String(containsName))
		nl, ok := res.Value().(*sbom.NodeList)
		require.True(t, ok, "%v", res)
		require.Len(t, nl.Nodes, 4)

		// The relationship carries the requested type, not dependsOn:
		found := false
		for _, e := range nl.Edges {
			if e.From == leafNodeID && e.Type == sbom.Edge_contains {
				require.Equal(t, []string{incomingID}, e.To)
				found = true
			}
		}
		require.True(t, found, "the new relationship must use the requested type")

		require.Len(t, sut.Nodes, 3, "the original nodelist is not modified")
		require.Len(t, sut.Edges, 2, "the original nodelist is not modified")
	})

	t.Run("on a document", func(t *testing.T) {
		sut := &elements.Document{
			Document: &sbom.Document{
				Metadata: &sbom.Metadata{Id: "test-doc"},
				NodeList: testGraphNodeList().NodeList,
			},
		}
		res := RelateNodeListAtID(sut, incoming, types.String(leafNodeID), types.String(containsName))
		doc, ok := res.Value().(*sbom.Document)
		require.True(t, ok, "%v", res)
		require.Len(t, doc.NodeList.Nodes, 4)
		require.Equal(t, "test-doc", doc.Metadata.Id)
		require.Len(t, sut.NodeList.Nodes, 3, "the original document is not modified")
	})

	t.Run("an unknown relationship type errors", func(t *testing.T) {
		res := RelateNodeListAtID(testGraphNodeList(), incoming, types.String(leafNodeID), types.String("not-a-type"))
		require.True(t, types.IsError(res))
	})
}
