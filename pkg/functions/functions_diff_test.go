// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors

package functions

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"github.com/protobom/cel/pkg/elements"
)

// diffMapGet reads one key of a diff report map.
func diffMapGet(t *testing.T, res ref.Val, key string) ref.Val {
	t.Helper()
	require.False(t, types.IsError(res), "%v", res)
	mapper, ok := res.(traits.Mapper)
	require.True(t, ok, "the diff report must be a map, got %T", res)
	return mapper.Get(types.String(key))
}

func TestFunctionDiffNodeList(t *testing.T) {
	t.Run("equal lists report zero changes", func(t *testing.T) {
		res := Diff(testGraphNodeList(), testGraphNodeList())
		require.Equal(t, types.Int(0), diffMapGet(t, res, "count"))
	})

	t.Run("an added node is reported", func(t *testing.T) {
		other := testGraphNodeList()
		other.AddNode(&sbom.Node{Id: "new-node"})
		res := Diff(testGraphNodeList(), other)
		require.Equal(t, types.Int(1), diffMapGet(t, res, "count"))
		added, ok := diffMapGet(t, res, "added").(traits.Lister)
		require.True(t, ok)
		require.Equal(t, types.Int(1), added.Size())
	})

	t.Run("the id flag is honored", func(t *testing.T) {
		// The node carries a purl so a renamed copy still pairs by
		// software identity.
		build := func(id string) *elements.NodeList {
			return &elements.NodeList{
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{{
						Id:   id,
						Name: "app",
						Identifiers: map[int32]string{
							int32(sbom.SoftwareIdentifierType_PURL): "pkg:generic/app@1.0.0",
						},
					}},
					Edges:        []*sbom.Edge{},
					RootElements: []string{id},
				},
			}
		}

		res := Diff(build("one-id"), build("another-id"))
		require.Equal(t, types.Int(0), diffMapGet(t, res, "count"),
			"identifier changes do not count by default")

		res = Diff(build("one-id"), build("another-id"), types.True)
		count, ok := diffMapGet(t, res, "count").Value().(int64)
		require.True(t, ok)
		require.Positive(t, count, "with the flag, identifier changes count")
	})

	t.Run("mismatched operands error", func(t *testing.T) {
		res := Diff(testGraphNodeList(), types.String("not a nodelist"))
		require.True(t, types.IsError(res))
	})
}

func TestFunctionDiffDocument(t *testing.T) {
	doc := func() *elements.Document {
		return &elements.Document{
			Document: &sbom.Document{
				Metadata: &sbom.Metadata{Id: "test-doc", Version: "1"},
				NodeList: testGraphNodeList().NodeList,
			},
		}
	}

	t.Run("equal documents report zero changes", func(t *testing.T) {
		res := Diff(doc(), doc())
		require.Equal(t, types.Int(0), diffMapGet(t, res, "count"))
	})

	t.Run("metadata changes are reported", func(t *testing.T) {
		other := doc()
		other.Metadata.Version = "2"
		res := Diff(doc(), other)
		require.Equal(t, types.Int(1), diffMapGet(t, res, "count"))
		md, ok := diffMapGet(t, res, "metadata").(traits.Mapper)
		require.True(t, ok)
		require.Equal(t, types.Int(1), md.Get(types.String("count")))
	})
}

func TestFunctionDiffNode(t *testing.T) {
	node := func() *elements.Node {
		return &elements.Node{Node: &sbom.Node{Id: "a", Name: "app", Version: "1.0.0"}}
	}

	t.Run("equal nodes report zero changes", func(t *testing.T) {
		res := Diff(node(), node())
		require.Equal(t, types.Int(0), diffMapGet(t, res, "count"))
	})

	t.Run("a changed field is reported", func(t *testing.T) {
		other := node()
		other.Version = "2.0.0"
		res := Diff(node(), other)
		require.Equal(t, types.Int(1), diffMapGet(t, res, "count"))
		added, ok := diffMapGet(t, res, "added").Value().(*sbom.Node)
		require.True(t, ok)
		require.Equal(t, "2.0.0", added.Version)
	})
}
