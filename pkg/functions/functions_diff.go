// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors

package functions

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/protobom/cel/pkg/adapter"
	"github.com/protobom/cel/pkg/elements"
)

// Diff compares two documents, nodelists or nodes and returns a map
// describing the changes that transform the first into the second. The map
// always carries a "count" entry totaling the changes, so two equivalent
// elements produce {"count": 0}.
//
// By default, identifier changes do not count as changes, following the
// protobom diff semantics; passing true as the extra argument compares them
// too.
func Diff(vals ...ref.Val) ref.Val {
	if len(vals) != 2 && len(vals) != 3 {
		return types.NewErr("incorrect number of params")
	}

	options := []sbom.DiffOption{}
	if len(vals) == 3 {
		withIDs, ok := vals[2].Value().(bool)
		if !ok {
			return types.NewErr("the ID comparison flag must be a boolean, not %T", vals[2].Value())
		}
		if withIDs {
			options = append(options, sbom.WithIDs())
		}
	}

	switch v := vals[0].Value().(type) {
	case *sbom.NodeList:
		other, ok := vals[1].Value().(*sbom.NodeList)
		if !ok {
			return types.NewErr("a nodelist can only be diffed against another nodelist, not %T", vals[1].Value())
		}
		return newDiffMap(nodeListDiffToMap(v.Diff(other, options...)))
	case *sbom.Document:
		other, ok := vals[1].Value().(*sbom.Document)
		if !ok {
			return types.NewErr("a document can only be diffed against another document, not %T", vals[1].Value())
		}
		return newDiffMap(documentDiffToMap(v.Diff(other, options...)))
	case *sbom.Node:
		other, ok := vals[1].Value().(*sbom.Node)
		if !ok {
			return types.NewErr("a node can only be diffed against another node, not %T", vals[1].Value())
		}
		return newDiffMap(nodeDiffToMap(v.Diff(other, options...)))
	default:
		return types.NewErr("diff unsupported on type %T", vals[0].Value())
	}
}

// diffCountKey is the report entry totaling the changes, present in every
// diff report map.
const diffCountKey = "count"

// newDiffMap converts a diff report map to a CEL value.
func newDiffMap(m map[string]any) ref.Val {
	return types.NewStringInterfaceMap(adapter.ProtobomTypeAdapter{}, m)
}

// nodeDiffToMap flattens a node diff report. A nil diff means no changes and
// produces {"count": 0}.
func nodeDiffToMap(nd *sbom.NodeDiff) map[string]any {
	if nd == nil {
		return map[string]any{diffCountKey: 0}
	}
	m := map[string]any{diffCountKey: nd.DiffCount}
	if nd.Added != nil {
		m["added"] = &elements.Node{Node: nd.Added}
	}
	if nd.Removed != nil {
		m["removed"] = &elements.Node{Node: nd.Removed}
	}
	if nd.Node1 != nil {
		m["before"] = &elements.Node{Node: nd.Node1}
	}
	if nd.Node2 != nil {
		m["after"] = &elements.Node{Node: nd.Node2}
	}
	return m
}

// nodeListDiffToMap flattens a nodelist diff report. A nil diff means no
// changes and produces {"count": 0}.
func nodeListDiffToMap(d *sbom.NodeListDiff) map[string]any {
	if d == nil {
		return map[string]any{diffCountKey: 0}
	}

	wrapNodes := func(nodes []*sbom.Node) []ref.Val {
		l := make([]ref.Val, 0, len(nodes))
		for _, n := range nodes {
			l = append(l, &elements.Node{Node: n})
		}
		return l
	}
	wrapEdges := func(edges []*sbom.Edge) []ref.Val {
		l := make([]ref.Val, 0, len(edges))
		for _, e := range edges {
			l = append(l, &elements.Edge{Edge: e})
		}
		return l
	}

	modified := make([]any, 0, len(d.Modified))
	for _, nd := range d.Modified {
		modified = append(modified, nodeDiffToMap(nd))
	}

	return map[string]any{
		diffCountKey:            d.DiffCount,
		"added":                 wrapNodes(d.Added),
		"removed":               wrapNodes(d.Removed),
		"modified":              modified,
		"edges_added":           wrapEdges(d.EdgesAdded),
		"edges_removed":         wrapEdges(d.EdgesRemoved),
		"root_elements_added":   d.RootElementsAdded,
		"root_elements_removed": d.RootElementsRemoved,
	}
}

// documentDiffToMap flattens a document diff report. A nil diff means no
// changes and produces {"count": 0}. The metadata and nodelist reports are
// present only when they carry changes.
func documentDiffToMap(d *sbom.DocumentDiff) map[string]any {
	if d == nil {
		return map[string]any{diffCountKey: 0}
	}
	m := map[string]any{diffCountKey: d.DiffCount}
	if d.Metadata != nil {
		md := map[string]any{diffCountKey: d.Metadata.DiffCount}
		if d.Metadata.Added != nil {
			md["added"] = &elements.Metadata{Metadata: d.Metadata.Added}
		}
		if d.Metadata.Removed != nil {
			md["removed"] = &elements.Metadata{Metadata: d.Metadata.Removed}
		}
		m["metadata"] = md
	}
	if d.NodeList != nil {
		m["nodelist"] = nodeListDiffToMap(d.NodeList)
	}
	return m
}
