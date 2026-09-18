// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2026 The Protobom Authors

package functions

import (
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"github.com/protobom/protobom/pkg/sbom"
	"google.golang.org/protobuf/proto"

	"github.com/protobom/cel/pkg/elements"
)

// copyDocument returns a document sharing nothing with the original: the
// metadata is cloned and the node list copied. The composition functions
// keep CEL value semantics, so they work on copies.
func copyDocument(doc *sbom.Document) *sbom.Document {
	out := &sbom.Document{NodeList: sbom.NewNodeList()}
	if doc.GetMetadata() != nil {
		out.Metadata = proto.Clone(doc.GetMetadata()).(*sbom.Metadata) //nolint:errcheck,forcetypeassert // Clone preserves the type
	}
	if doc.GetNodeList() != nil {
		out.NodeList = doc.GetNodeList().Copy()
	}
	return out
}

// Absorb returns a copy of the receiver completed with what the argument
// knows: fields it lacks are filled and collections are merged entry by
// entry, without overriding anything the receiver states. Documents absorb
// documents, node lists absorb node lists and nodes absorb nodes.
var Absorb = func(lhs, rhs ref.Val) ref.Val {
	switch v := lhs.Value().(type) {
	case *sbom.Document:
		other, ok := rhs.Value().(*sbom.Document)
		if !ok {
			return types.NewErr("a document can only absorb a document, not %T", rhs.Value())
		}
		doc := copyDocument(v)
		doc.Absorb(other)
		return &elements.Document{Document: doc}
	case *sbom.NodeList:
		other, ok := rhs.Value().(*sbom.NodeList)
		if !ok {
			return types.NewErr("a nodelist can only absorb a nodelist, not %T", rhs.Value())
		}
		nl := v.Copy()
		nl.Absorb(other)
		return &elements.NodeList{NodeList: nl}
	case *sbom.Node:
		other, ok := rhs.Value().(*sbom.Node)
		if !ok {
			return types.NewErr("a node can only absorb a node, not %T", rhs.Value())
		}
		n := v.Copy()
		n.Absorb(other)
		return &elements.Node{Node: n}
	default:
		return types.NewErr("absorb is not supported on %T", lhs.Value())
	}
}

// Dedupe returns a copy of the receiver in which the nodes describing the
// same component (see SameComponent) are collapsed into one, with every
// relationship rewired to the survivor.
var Dedupe = func(val ref.Val) ref.Val {
	switch v := val.Value().(type) {
	case *sbom.Document:
		doc := copyDocument(v)
		doc.NodeList.Dedupe(nil)
		return &elements.Document{Document: doc}
	case *sbom.NodeList:
		nl := v.Copy()
		nl.Dedupe(nil)
		return &elements.NodeList{NodeList: nl}
	default:
		return types.NewErr("dedupe is not supported on %T", val.Value())
	}
}

// SameComponent reports whether two nodes describe the same component: the
// same kind of node, agreeing on every hash algorithm they share, or, when
// they share none, carrying the same purl.
var SameComponent = func(lhs, rhs ref.Val) ref.Val {
	a, ok := lhs.Value().(*sbom.Node)
	if !ok {
		return types.NewErr("same_component only applies to a node, not %T", lhs.Value())
	}
	b, ok := rhs.Value().(*sbom.Node)
	if !ok {
		return types.NewErr("a node can only be compared to a node, not %T", rhs.Value())
	}
	return types.Bool(sbom.SameComponent(a, b))
}

// HashesConflict reports whether two nodes state different values for a
// hash algorithm they both carry.
var HashesConflict = func(lhs, rhs ref.Val) ref.Val {
	a, ok := lhs.Value().(*sbom.Node)
	if !ok {
		return types.NewErr("hashes_conflict only applies to a node, not %T", lhs.Value())
	}
	b, ok := rhs.Value().(*sbom.Node)
	if !ok {
		return types.NewErr("a node can only be compared to a node, not %T", rhs.Value())
	}
	return types.Bool(a.HashesConflict(b))
}

// Graft returns a copy of the receiver with the graph reachable from a node
// of another node list hung under one of its nodes. Arguments: the id of
// the node to graft at, the source node list, the id of the source node to
// start from, and the name of the relationship type.
var Graft = func(vals ...ref.Val) ref.Val {
	if len(vals) != 5 {
		return types.NewErr("invalid number of arguments for graft")
	}
	atID, ok := vals[1].Value().(string)
	if !ok {
		return types.NewErr("node id has to be a string")
	}
	src, ok := vals[2].Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("the source of a graft has to be a nodelist, not %T", vals[2].Value())
	}
	rootID, ok := vals[3].Value().(string)
	if !ok {
		return types.NewErr("source node id has to be a string")
	}
	typeName, ok := vals[4].Value().(string)
	if !ok {
		return types.NewErr("relationship type has to be a string")
	}
	edgeType, err := edgeTypeFromString(typeName)
	if err != nil {
		return types.NewErr("%v", err)
	}

	switch v := vals[0].Value().(type) {
	case *sbom.Document:
		doc := copyDocument(v)
		if err := doc.NodeList.Graft(atID, src, rootID, edgeType); err != nil {
			return types.NewErr("grafting: %v", err)
		}
		return &elements.Document{Document: doc}
	case *sbom.NodeList:
		nl := v.Copy()
		if err := nl.Graft(atID, src, rootID, edgeType); err != nil {
			return types.NewErr("grafting: %v", err)
		}
		return &elements.NodeList{NodeList: nl}
	default:
		return types.NewErr("graft is not supported on %T", vals[0].Value())
	}
}

// GraftInto returns a copy of the receiver in which one of its nodes has
// absorbed a node of another node list, with the graph reachable from that
// node hung below it. Arguments: the id of the node to graft into, the
// source node list and the id of the source node.
var GraftInto = func(vals ...ref.Val) ref.Val {
	if len(vals) != 4 {
		return types.NewErr("invalid number of arguments for graft_into")
	}
	atID, ok := vals[1].Value().(string)
	if !ok {
		return types.NewErr("node id has to be a string")
	}
	src, ok := vals[2].Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("the source of a graft has to be a nodelist, not %T", vals[2].Value())
	}
	rootID, ok := vals[3].Value().(string)
	if !ok {
		return types.NewErr("source node id has to be a string")
	}

	switch v := vals[0].Value().(type) {
	case *sbom.Document:
		doc := copyDocument(v)
		if err := doc.NodeList.GraftInto(atID, src, rootID); err != nil {
			return types.NewErr("grafting: %v", err)
		}
		return &elements.Document{Document: doc}
	case *sbom.NodeList:
		nl := v.Copy()
		if err := nl.GraftInto(atID, src, rootID); err != nil {
			return types.NewErr("grafting: %v", err)
		}
		return &elements.NodeList{NodeList: nl}
	default:
		return types.NewErr("graft_into is not supported on %T", vals[0].Value())
	}
}
