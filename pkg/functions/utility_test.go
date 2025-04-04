// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package functions

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"github.com/protobom/cel/pkg/elements"
)

func TestCleanEdges(t *testing.T) {
	const (
		node1 = "node1"
		node2 = "node2"
	)
	for _, tc := range []struct {
		sut      *elements.NodeList
		expected *elements.NodeList
	}{
		// Edge does not need to be modified
		{
			sut: &elements.NodeList{
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{
						{Id: node1}, {Id: node2},
					},
					Edges: []*sbom.Edge{
						{
							Type: sbom.Edge_UNKNOWN,
							From: node1,
							To:   []string{node2},
						},
					},
					RootElements: []string{node1},
				},
			},
			expected: &elements.NodeList{
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{
						{Id: node1}, {Id: node2},
					},
					Edges: []*sbom.Edge{
						{
							Type: sbom.Edge_UNKNOWN,
							From: node1,
							To:   []string{node2},
						},
					},
					RootElements: []string{node1},
				},
			},
		},
		// Edge contains a broken To
		{
			sut: &elements.NodeList{
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{
						{Id: node1}, {Id: node2},
					},
					Edges: []*sbom.Edge{
						{
							Type: sbom.Edge_UNKNOWN,
							From: node1,
							To:   []string{node2, "node3"},
						},
					},
					RootElements: []string{node1},
				},
			},
			expected: &elements.NodeList{
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{
						{Id: node1}, {Id: node2},
					},
					Edges: []*sbom.Edge{
						{
							Type: sbom.Edge_UNKNOWN,
							From: node1,
							To:   []string{node2},
						},
					},
					RootElements: []string{node1},
				},
			},
		},
		// Edge contains a broken From
		{
			sut: &elements.NodeList{
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{
						{Id: node1}, {Id: node2},
					},
					Edges: []*sbom.Edge{
						{
							Type: sbom.Edge_UNKNOWN,
							From: "node3",
							To:   []string{node1},
						},
					},
					RootElements: []string{node1},
				},
			},
			expected: &elements.NodeList{
				NodeList: &sbom.NodeList{
					Nodes: []*sbom.Node{
						{Id: node1}, {Id: node2},
					},
					Edges:        []*sbom.Edge{},
					RootElements: []string{node1},
				},
			},
		},
	} {
		cleanEdges(tc.sut)
		require.Equal(t, tc.expected, tc.sut)
	}
}
