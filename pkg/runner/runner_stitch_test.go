// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors

package runner

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"
)

const (
	stitchSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	imageID      = "image"
	binID        = "bin"
	dupID        = "dup"
	appID        = "app"
	libID        = "lib"
	mitLicense   = "MIT"
)

// stitchDocuments returns two documents: the first holds a file, the
// second describes that file's package with a dependency.
func stitchDocuments() []*sbom.Document {
	found := &sbom.Document{
		Metadata: &sbom.Metadata{Id: "found"},
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{Id: imageID, Type: sbom.Node_PACKAGE, Name: imageID},
				{Id: binID, Type: sbom.Node_FILE, Name: binID, Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA256): stitchSHA256}},
				{Id: dupID, Type: sbom.Node_FILE, Name: dupID, Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA256): stitchSHA256}},
			},
			Edges:        []*sbom.Edge{{Type: sbom.Edge_contains, From: imageID, To: []string{binID, dupID}}},
			RootElements: []string{imageID},
		},
	}
	supplement := &sbom.Document{
		Metadata: &sbom.Metadata{Id: "supplement", Tools: []*sbom.Tool{{Name: "tool"}}},
		NodeList: &sbom.NodeList{
			Nodes: []*sbom.Node{
				{Id: appID, Type: sbom.Node_PACKAGE, Name: appID, Licenses: []string{mitLicense}, Hashes: map[int32]string{int32(sbom.HashAlgorithm_SHA256): stitchSHA256}},
				{Id: libID, Type: sbom.Node_PACKAGE, Name: libID},
			},
			Edges:        []*sbom.Edge{{Type: sbom.Edge_dependsOn, From: appID, To: []string{libID}}},
			RootElements: []string{appID},
		},
	}
	return []*sbom.Document{found, supplement}
}

// TestStitchFunctionsEvaluate compiles and evaluates each of the stitching
// functions through the CEL environment, which proves the declarations
// bind to the implementations with the right arity and types.
func TestStitchFunctionsEvaluate(t *testing.T) {
	r, err := NewRunner()
	require.NoError(t, err)
	docs := stitchDocuments()
	vars, err := BuildVariables(WithDocuments(docs))
	require.NoError(t, err)

	eval := func(code string) any {
		t.Helper()
		res, err := r.Evaluate(code, vars)
		require.NoError(t, err, code)
		return res.Value()
	}
	asDoc := func(v any) *sbom.Document {
		t.Helper()
		doc, ok := v.(*sbom.Document)
		require.True(t, ok, "not a document: %T", v)
		return doc
	}
	asNode := func(v any) *sbom.Node {
		t.Helper()
		n, ok := v.(*sbom.Node)
		require.True(t, ok, "not a node: %T", v)
		return n
	}
	nodes := func(v any) []*sbom.Node {
		t.Helper()
		switch x := v.(type) {
		case *sbom.NodeList:
			return x.Nodes
		case *sbom.Document:
			return x.NodeList.Nodes
		}
		t.Fatalf("not a graph: %T", v)
		return nil
	}

	// graft: the supplement's graph hangs under the file.
	require.Len(t, nodes(eval(`sboms[0].to_node_list().graft("bin", sboms[1].to_node_list(), "app", "generatedFrom")`)), 5)
	// graft_into on a document: the file absorbs the package.
	doc := asDoc(eval(`sboms[0].graft_into("bin", sboms[1].to_node_list(), "app")`))
	require.Len(t, doc.NodeList.Nodes, 4)
	require.Equal(t, []string{mitLicense}, doc.NodeList.GetNodeByID(binID).Licenses)
	// dedupe: the two files with the same hash become one.
	require.Len(t, nodes(eval(`sboms[0].dedupe()`)), 2)
	require.Len(t, nodes(eval(`sboms[0].to_node_list().dedupe()`)), 2)
	// absorb on every level.
	absorbed := asDoc(eval(`sboms[0].absorb(sboms[1])`))
	require.Len(t, absorbed.NodeList.Nodes, 5)
	require.Len(t, absorbed.Metadata.Tools, 1)
	require.Len(t, nodes(eval(`sboms[0].to_node_list().absorb(sboms[1].to_node_list())`)), 5)
	require.Equal(t, []string{mitLicense}, asNode(eval(`sboms[0].get_node_by_id("bin").absorb(sboms[1].get_node_by_id("app"))`)).Licenses)
	// identity predicates.
	require.Equal(t, true, eval(`sboms[0].get_node_by_id("bin").same_component(sboms[0].get_node_by_id("dup"))`))
	require.Equal(t, false, eval(`sboms[0].get_node_by_id("bin").same_component(sboms[1].get_node_by_id("app"))`), "a file and a package")
	require.Equal(t, false, eval(`sboms[0].get_node_by_id("bin").hashes_conflict(sboms[1].get_node_by_id("app"))`))

	// The inputs are never modified.
	require.Len(t, docs[0].NodeList.Nodes, 3)
	require.Empty(t, docs[0].NodeList.GetNodeByID(binID).Licenses)
	require.Len(t, docs[1].NodeList.Nodes, 2)
}
