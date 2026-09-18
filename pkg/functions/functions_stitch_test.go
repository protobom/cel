// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors

package functions

import (
	"testing"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"github.com/protobom/cel/pkg/elements"
)

const (
	testSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	appNodeID  = "app"
	libNodeID  = "lib"
	mitLicense = "MIT"
)

func stitchNode(id, purl string, hashes ...string) *sbom.Node {
	n := &sbom.Node{Id: id, Type: sbom.Node_PACKAGE, Name: id}
	if purl != "" {
		n.Identifiers = map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): purl}
	}
	if len(hashes) > 0 {
		n.Hashes = map[int32]string{int32(sbom.HashAlgorithm_SHA256): hashes[0]}
	}
	return n
}

func TestFunctionAbsorb(t *testing.T) {
	t.Run("node", func(t *testing.T) {
		a := &elements.Node{Node: &sbom.Node{Id: "a", Name: "a", Licenses: []string{mitLicense}}}
		b := &elements.Node{Node: &sbom.Node{Id: "b", Version: "2", Licenses: []string{"Apache-2.0"}}}
		res := Absorb(a, b)
		n, ok := res.Value().(*sbom.Node)
		require.True(t, ok, "%v", res)
		require.Equal(t, "a", n.Name)
		require.Equal(t, "2", n.Version)
		require.Equal(t, []string{mitLicense, "Apache-2.0"}, n.Licenses)
		require.Equal(t, []string{mitLicense}, a.Licenses, "the receiver is not modified")
	})

	t.Run("nodelist", func(t *testing.T) {
		nl := testGraphNodeList()
		other := &elements.NodeList{NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{{Id: midNodeID, Licenses: []string{mitLicense}}, {Id: "new"}},
		}}
		res := Absorb(nl, other)
		out, ok := res.Value().(*sbom.NodeList)
		require.True(t, ok, "%v", res)
		require.Len(t, out.Nodes, 4)
		require.Equal(t, []string{mitLicense}, out.GetNodeByID(midNodeID).Licenses)
		require.Len(t, nl.Nodes, 3, "the receiver is not modified")
	})

	t.Run("document", func(t *testing.T) {
		doc := &elements.Document{Document: &sbom.Document{
			Metadata: &sbom.Metadata{Id: "one"},
			NodeList: testGraphNodeList().NodeList,
		}}
		other := &elements.Document{Document: &sbom.Document{
			Metadata: &sbom.Metadata{Id: "two", Name: "second", Tools: []*sbom.Tool{{Name: "tool"}}},
			NodeList: &sbom.NodeList{Nodes: []*sbom.Node{{Id: "new"}}},
		}}
		res := Absorb(doc, other)
		out, ok := res.Value().(*sbom.Document)
		require.True(t, ok, "%v", res)
		require.Equal(t, "one", out.Metadata.Id)
		require.Equal(t, "second", out.Metadata.Name)
		require.Len(t, out.Metadata.Tools, 1)
		require.Len(t, out.NodeList.Nodes, 4)
		require.Empty(t, doc.Metadata.Name, "the receiver is not modified")
		require.Len(t, doc.NodeList.Nodes, 3)
	})

	t.Run("errors", func(t *testing.T) {
		require.True(t, types.IsError(Absorb(testGraphNodeList(), types.String("x"))))
		require.True(t, types.IsError(Absorb(types.String("x"), testGraphNodeList())))
		require.True(t, types.IsError(Absorb(&elements.Node{Node: &sbom.Node{}}, testGraphNodeList())))
	})
}

func TestFunctionDedupe(t *testing.T) {
	nl := &elements.NodeList{NodeList: &sbom.NodeList{
		Nodes: []*sbom.Node{
			stitchNode(rootNodeID, "pkg:x/root@1"),
			stitchNode("a", "pkg:x/lib@1", testSHA256),
			stitchNode("a2", "pkg:x/lib@1", testSHA256),
		},
		Edges:        []*sbom.Edge{{Type: sbom.Edge_dependsOn, From: rootNodeID, To: []string{"a", "a2"}}},
		RootElements: []string{rootNodeID},
	}}

	res := Dedupe(nl)
	out, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, out.Nodes, 2)
	require.Equal(t, []string{"a"}, out.Edges[0].To)
	require.Len(t, nl.Nodes, 3, "the receiver is not modified")

	res = Dedupe(&elements.Document{Document: &sbom.Document{Metadata: &sbom.Metadata{Id: "d"}, NodeList: nl.NodeList}})
	doc, ok := res.Value().(*sbom.Document)
	require.True(t, ok, "%v", res)
	require.Len(t, doc.NodeList.Nodes, 2)
	require.Equal(t, "d", doc.Metadata.Id)

	require.True(t, types.IsError(Dedupe(types.String("x"))))
}

func TestFunctionSameComponentAndHashesConflict(t *testing.T) {
	a := &elements.Node{Node: stitchNode("a", "pkg:x/lib@1", testSHA256)}
	same := &elements.Node{Node: stitchNode("b", "pkg:x/other@2", testSHA256)}
	conflicting := &elements.Node{Node: stitchNode("c", "pkg:x/lib@1", "0000000000000000000000000000000000000000000000000000000000000000")}
	purlOnly := &elements.Node{Node: stitchNode("d", "pkg:x/lib@1")}

	require.Equal(t, types.True, SameComponent(a, same))
	require.Equal(t, types.False, SameComponent(a, conflicting))
	require.Equal(t, types.True, SameComponent(a, purlOnly))
	require.Equal(t, types.False, HashesConflict(a, same))
	require.Equal(t, types.True, HashesConflict(a, conflicting))
	require.Equal(t, types.False, HashesConflict(a, purlOnly))

	require.True(t, types.IsError(SameComponent(a, types.String("x"))))
	require.True(t, types.IsError(SameComponent(types.String("x"), a)))
	require.True(t, types.IsError(HashesConflict(a, types.String("x"))))
	require.True(t, types.IsError(HashesConflict(types.String("x"), a)))
}

func TestFunctionGraft(t *testing.T) {
	src := &elements.NodeList{NodeList: &sbom.NodeList{
		Nodes:        []*sbom.Node{{Id: appNodeID, Name: appNodeID}, {Id: libNodeID, Name: libNodeID}, {Id: "stray", Name: "stray"}},
		Edges:        []*sbom.Edge{{Type: sbom.Edge_dependsOn, From: appNodeID, To: []string{libNodeID}}},
		RootElements: []string{appNodeID},
	}}

	res := Graft(testGraphNodeList(), types.String(leafNodeID), src, types.String(appNodeID), types.String("generatedFrom"))
	out, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, out.Nodes, 5, "root, mid, leaf and the copies of app and lib")
	require.Nil(t, out.GetNodeByID(appNodeID), "copies carry fresh ids")
	edge := out.GetEdgeByType(leafNodeID, sbom.Edge_generatedFrom)
	require.NotNil(t, edge)
	require.Equal(t, appNodeID, out.GetNodeByID(edge.To[0]).Name)

	// Document receiver, and value semantics on both sides.
	doc := &elements.Document{Document: &sbom.Document{Metadata: &sbom.Metadata{Id: "d"}, NodeList: testGraphNodeList().NodeList}}
	res = Graft(doc, types.String(leafNodeID), src, types.String(appNodeID), types.String("contains"))
	outDoc, ok := res.Value().(*sbom.Document)
	require.True(t, ok, "%v", res)
	require.Len(t, outDoc.NodeList.Nodes, 5)
	require.Len(t, doc.NodeList.Nodes, 3, "the receiver is not modified")
	require.Len(t, src.Nodes, 3, "the source is not modified")

	for _, bad := range [][]ref.Val{
		{types.String("nope"), src, types.String(appNodeID), types.String("contains")},
		{types.String(leafNodeID), src, types.String("nope"), types.String("contains")},
		{types.String(leafNodeID), src, types.String(appNodeID), types.String("notAType")},
		{types.String(leafNodeID), types.String("x"), types.String(appNodeID), types.String("contains")},
		{types.Int(1), src, types.String(appNodeID), types.String("contains")},
	} {
		res := Graft(append([]ref.Val{testGraphNodeList()}, bad...)...)
		require.True(t, types.IsError(res), "%v", bad)
	}
	require.True(t, types.IsError(Graft(testGraphNodeList())))
	require.True(t, types.IsError(Graft(types.String("x"), types.String(leafNodeID), src, types.String(appNodeID), types.String("contains"))))
}

func TestFunctionGraftInto(t *testing.T) {
	src := &elements.NodeList{NodeList: &sbom.NodeList{
		Nodes:        []*sbom.Node{{Id: appNodeID, Name: appNodeID, Licenses: []string{mitLicense}}, {Id: libNodeID, Name: libNodeID}},
		Edges:        []*sbom.Edge{{Type: sbom.Edge_dependsOn, From: appNodeID, To: []string{libNodeID}}},
		RootElements: []string{appNodeID},
	}}

	res := GraftInto(testGraphNodeList(), types.String(leafNodeID), src, types.String(appNodeID))
	out, ok := res.Value().(*sbom.NodeList)
	require.True(t, ok, "%v", res)
	require.Len(t, out.Nodes, 4, "root, mid, leaf and the copy of lib")
	leaf := out.GetNodeByID(leafNodeID)
	require.Equal(t, []string{mitLicense}, leaf.Licenses, "the leaf absorbed app")
	edge := out.GetEdgeByType(leafNodeID, sbom.Edge_dependsOn)
	require.NotNil(t, edge)
	require.Equal(t, libNodeID, out.GetNodeByID(edge.To[0]).Name)

	doc := &elements.Document{Document: &sbom.Document{NodeList: testGraphNodeList().NodeList}}
	res = GraftInto(doc, types.String(leafNodeID), src, types.String(appNodeID))
	outDoc, ok := res.Value().(*sbom.Document)
	require.True(t, ok, "%v", res)
	require.Len(t, outDoc.NodeList.Nodes, 4)
	require.Len(t, doc.NodeList.Nodes, 3, "the receiver is not modified")

	require.True(t, types.IsError(GraftInto(testGraphNodeList(), types.String("nope"), src, types.String(appNodeID))))
	require.True(t, types.IsError(GraftInto(testGraphNodeList(), types.String(leafNodeID), src, types.String("nope"))))
	require.True(t, types.IsError(GraftInto(testGraphNodeList(), types.String(leafNodeID), types.String("x"), types.String(appNodeID))))
	require.True(t, types.IsError(GraftInto(testGraphNodeList())))
	require.True(t, types.IsError(GraftInto(types.String("x"), types.String(leafNodeID), src, types.String(appNodeID))))
}
