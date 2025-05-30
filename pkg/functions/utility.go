// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package functions

import (
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/protobom/cel/pkg/elements"
)

// cleanEdges removes all edges that have broken Froms and removes
// any destination IDs from elements not in the NodeList.
func cleanEdges(nl *elements.NodeList) {
	// First copy the nodelist edges
	newEdges := []*sbom.Edge{}

	// Build a catalog of the elements ids
	idDict := map[string]struct{}{}
	for i := range nl.Nodes {
		idDict[nl.Nodes[i].Id] = struct{}{}
	}

	// Now list all edges and rebuild the list
	for _, edge := range nl.Edges {
		newTos := []string{}
		if _, ok := idDict[edge.From]; !ok {
			continue
		}

		for _, s := range edge.To {
			if _, ok := idDict[s]; ok {
				newTos = append(newTos, s)
			}
		}

		if len(newTos) == 0 {
			continue
		}

		edge.To = newTos
		newEdges = append(newEdges, edge)
	}

	nl.Edges = newEdges
}

// reconnectOrphanNodes cleans the graph structure by reconnecting all
// orphaned nodes to the top of the graph
func reconnectOrphanNodes(nl *elements.NodeList) {
	edgeIndex := map[string]struct{}{}
	rootIndex := map[string]struct{}{}

	for _, e := range nl.Edges {
		for _, t := range e.To {
			edgeIndex[t] = struct{}{}
		}
	}

	for _, id := range nl.RootElements {
		rootIndex[id] = struct{}{}
	}

	for _, n := range nl.Nodes {
		if _, ok := edgeIndex[n.Id]; !ok {
			if _, ok := rootIndex[n.Id]; !ok {
				nl.RootElements = append(nl.RootElements, n.Id)
			}
		}
	}
}
