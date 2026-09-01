// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package library

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/protobom/cel/pkg/elements"
	"github.com/protobom/cel/pkg/functions"
)

// Functions returns the compile-time options that define the functions that
// the protobom library exposes to the cel environment.
func (p *Protobom) Functions() []cel.EnvOption {
	envopt := []cel.EnvOption{
		cel.Function(
			"get_files",
			cel.MemberOverload(
				"sbom_files_binding", []*types.Type{elements.DocumentType}, elements.NodeListType,
				cel.UnaryBinding(functions.Files),
			),
			cel.MemberOverload(
				"nodelist_files_binding", []*cel.Type{elements.NodeListType}, elements.NodeListType,
				cel.UnaryBinding(functions.Files),
			),
			cel.MemberOverload(
				"node_files_binding", []*cel.Type{elements.NodeType}, elements.NodeListType,
				cel.UnaryBinding(functions.Files),
			),
		),

		cel.Function(
			"get_packages",
			cel.MemberOverload(
				"sbom_packages_binding", []*cel.Type{elements.DocumentType}, elements.NodeListType,
				cel.UnaryBinding(functions.Packages),
			),
			cel.MemberOverload(
				"nodeslist_packages_binding", []*cel.Type{elements.NodeListType}, elements.NodeListType,
				cel.UnaryBinding(functions.Packages),
			),
			cel.MemberOverload(
				"node_packages_binding", []*cel.Type{elements.NodeType}, elements.NodeListType,
				cel.UnaryBinding(functions.Packages),
			),
		),

		cel.Function(
			"add",
			cel.MemberOverload(
				"add_nodelists",
				[]*cel.Type{elements.NodeListType, elements.NodeListType},
				elements.NodeListType,
				cel.BinaryBinding(functions.Addition),
				// cel.OverloadOperandTrait(traits.AdderType),
			),
		),

		cel.Function(
			"to_node_list",
			cel.MemberOverload(
				"document_tonodelist_binding",
				[]*cel.Type{elements.DocumentType}, elements.NodeListType,
				cel.UnaryBinding(functions.ToNodeList),
			),
			cel.MemberOverload(
				"nodelist_tonodelist_binding",
				[]*cel.Type{elements.NodeListType}, elements.NodeListType,
				cel.UnaryBinding(functions.ToNodeList),
			),
			cel.MemberOverload(
				"node_tonodelist_binding",
				[]*cel.Type{elements.NodeType}, elements.NodeListType,
				cel.UnaryBinding(functions.ToNodeList),
			),
		),

		// NodeByID returns a node looking it up by its identifier
		// Overloaded in: Document and NodeList.
		cel.Function(
			"get_node_by_id",
			cel.MemberOverload(
				"sbom_nodebyid_binding", []*cel.Type{elements.DocumentType, cel.StringType}, elements.NodeType,
				cel.BinaryBinding(functions.NodeByID),
			),
			cel.MemberOverload(
				"nodelist_nodebyid_binding", []*cel.Type{elements.NodeListType, cel.StringType}, elements.NodeType,
				cel.BinaryBinding(functions.NodeByID),
			),
		),

		// NodesByPurlType returns a NodeList including all nodes that have a
		// package URL of a certain type.
		// Overloaded in: Document and NodeList.
		cel.Function(
			"get_nodes_by_purl_type",
			cel.MemberOverload(
				"sbom_nodesbypurltype_binding", []*cel.Type{elements.DocumentType, cel.StringType}, elements.NodeListType,
				cel.BinaryBinding(functions.NodesByPurlType),
			),
			cel.MemberOverload(
				"nodelist_nodesbypurltype_binding", []*cel.Type{elements.NodeListType, cel.StringType}, elements.NodeListType,
				cel.BinaryBinding(functions.NodesByPurlType),
			),
		),

		// NodesByPurlType returns a NodeList including all nodes that have a
		// package URL of a certain type.
		// Overloaded in: Document and NodeList.
		cel.Function(
			"get_root_nodes",
			cel.MemberOverload(
				"doc_rootnodes_binding", []*cel.Type{elements.DocumentType}, cel.ListType(cel.DynType),
				cel.UnaryBinding(functions.RootNodes),
			),
			cel.MemberOverload(
				"nodelist_rootnodes_binding", []*cel.Type{elements.NodeListType}, cel.ListType(cel.DynType),
				cel.UnaryBinding(functions.RootNodes),
			),
		),

		// get_suppliers returns the list of persons acting as suppliers in the node
		cel.Function(
			"get_suppliers",
			cel.MemberOverload(
				"node_getsuppliers_binding", []*cel.Type{elements.NodeType}, types.ListType,
				cel.UnaryBinding(functions.NodeGetSuppliers),
			),
		),

		// get_suppliers returns the list of persons acting as suppliers in the node
		cel.Function(
			"get_originators",
			cel.MemberOverload(
				"node_getoriginators_binding", []*cel.Type{elements.NodeType}, types.ListType,
				cel.UnaryBinding(functions.NodeGetOriginators),
			),
		),

		// Overloaded in: Document and NodeList.
		cel.Function(
			"get_nodes",
			cel.MemberOverload(
				"enodelist_get_nodes", []*cel.Type{elements.NodeListType}, types.NewListType(types.DynType),
				cel.UnaryBinding(functions.GetNodes),
			),
		),

		cel.Function(
			"get_edges",
			cel.MemberOverload(
				"enodelist_get_edges", []*cel.Type{elements.NodeListType}, types.NewListType(elements.EdgeType),
				cel.UnaryBinding(functions.GetEdges),
			),
		),

		// GetNodeList returns a document's NodeList
		cel.Function(
			"get_node_list",
			cel.MemberOverload(
				"sbom_get_node_list_binding", []*cel.Type{elements.DocumentType}, elements.NodeListType,
				cel.UnaryBinding(functions.GetNodeList),
			),
		),

		// GetMetadata returns a document's Metadata
		cel.Function(
			"get_metadata",
			cel.MemberOverload(
				"sbom_get_metadata_binding", []*cel.Type{elements.DocumentType}, elements.MetadataType,
				cel.UnaryBinding(functions.GetMetadata),
			),
		),

		// ToDocument wraps an element and returns a new Document
		// Overloaded in: Node NodeList and Document (noop)
		cel.Function(
			"to_document",
			cel.MemberOverload(
				"document_todocument_binding",
				[]*cel.Type{elements.DocumentType}, elements.DocumentType,
				cel.UnaryBinding(functions.ToDocument),
			),
			cel.MemberOverload(
				"nodelist_todocument_binding",
				[]*cel.Type{elements.NodeListType}, elements.DocumentType,
				cel.UnaryBinding(functions.ToDocument),
			),
			cel.MemberOverload(
				"node_todocument_binding",
				[]*cel.Type{elements.NodeType}, elements.DocumentType,
				cel.UnaryBinding(functions.ToDocument),
			),
		),

		cel.Function(
			"relate_node_list_at_id",
			cel.MemberOverload(
				"sbom_relatenodesatid_binding",
				[]*cel.Type{elements.DocumentType, elements.NodeListType, cel.StringType, cel.StringType},
				elements.DocumentType, // result
				cel.FunctionBinding(functions.RelateNodeListAtID),
			),
			cel.MemberOverload(
				"nodelist_relatenodesatid_binding",
				[]*cel.Type{elements.NodeListType, elements.NodeListType, cel.StringType, cel.StringType},
				elements.NodeListType, // result
				cel.FunctionBinding(functions.RelateNodeListAtID),
			),
		),
		cel.Function(
			"get_authors",
			cel.MemberOverload(
				"sbom_get_authors",
				[]*cel.Type{elements.DocumentType},
				types.ListType, // result
				cel.UnaryBinding(functions.GetAuthors),
			),
			cel.MemberOverload(
				"metadata_get_authors",
				[]*cel.Type{elements.MetadataType},
				types.ListType, // result
				cel.UnaryBinding(functions.GetAuthors),
			),
		),
		// NodeList API functions
		cel.Function(
			"get_nodes_by_name",
			cel.MemberOverload(
				"nodelist_nodes_by_name",
				[]*cel.Type{elements.NodeListType, types.StringType},
				types.ListType,
				cel.BinaryBinding(functions.GetNodesByName),
			),
		),
		cel.Function(
			"get_node_descendants",
			cel.MemberOverload(
				"nodelist_node_descendants",
				[]*cel.Type{elements.NodeListType, types.StringType, types.IntType},
				elements.NodeListType,
				cel.FunctionBinding(functions.NodeDescendants),
			),
		),
		// get_node_ancestors walks the graph upwards from a node, mirroring
		// get_node_descendants.
		cel.Function(
			"get_node_ancestors",
			cel.MemberOverload(
				"nodelist_node_ancestors",
				[]*cel.Type{elements.NodeListType, types.StringType, types.IntType},
				elements.NodeListType,
				cel.FunctionBinding(functions.NodeAncestors),
			),
		),
		// get_edges_from returns the edges originating at a node.
		cel.Function(
			"get_edges_from",
			cel.MemberOverload(
				"nodelist_get_edges_from",
				[]*cel.Type{elements.NodeListType, types.StringType},
				types.NewListType(elements.EdgeType),
				cel.BinaryBinding(functions.GetEdgesFrom),
			),
		),
		// get_edges_to returns the edges pointing to a node.
		cel.Function(
			"get_edges_to",
			cel.MemberOverload(
				"nodelist_get_edges_to",
				[]*cel.Type{elements.NodeListType, types.StringType},
				types.NewListType(elements.EdgeType),
				cel.BinaryBinding(functions.GetEdgesTo),
			),
		),
		// unrelate_nodes returns a new nodelist with one relationship
		// (from, to, type) removed.
		cel.Function(
			"unrelate_nodes",
			cel.MemberOverload(
				"nodelist_unrelate_nodes",
				[]*cel.Type{elements.NodeListType, types.StringType, types.StringType, types.StringType},
				elements.NodeListType,
				cel.FunctionBinding(functions.UnrelateNodes),
			),
		),
		// remove_edges_from returns a new nodelist without the edges of the
		// given type originating at a node.
		cel.Function(
			"remove_edges_from",
			cel.MemberOverload(
				"nodelist_remove_edges_from",
				[]*cel.Type{elements.NodeListType, types.StringType, types.StringType},
				elements.NodeListType,
				cel.FunctionBinding(functions.RemoveEdgesFrom),
			),
		),
		// diff compares two documents, nodelists or nodes and returns a map
		// describing the changes, always carrying a "count" entry. The
		// optional boolean makes identifier changes count as changes.
		cel.Function(
			"diff",
			cel.MemberOverload(
				"nodelist_diff",
				[]*cel.Type{elements.NodeListType, elements.NodeListType},
				types.NewMapType(types.StringType, types.DynType),
				cel.FunctionBinding(functions.Diff),
			),
			cel.MemberOverload(
				"nodelist_diff_ids",
				[]*cel.Type{elements.NodeListType, elements.NodeListType, types.BoolType},
				types.NewMapType(types.StringType, types.DynType),
				cel.FunctionBinding(functions.Diff),
			),
			cel.MemberOverload(
				"document_diff",
				[]*cel.Type{elements.DocumentType, elements.DocumentType},
				types.NewMapType(types.StringType, types.DynType),
				cel.FunctionBinding(functions.Diff),
			),
			cel.MemberOverload(
				"document_diff_ids",
				[]*cel.Type{elements.DocumentType, elements.DocumentType, types.BoolType},
				types.NewMapType(types.StringType, types.DynType),
				cel.FunctionBinding(functions.Diff),
			),
			cel.MemberOverload(
				"node_diff",
				[]*cel.Type{elements.NodeType, elements.NodeType},
				types.NewMapType(types.StringType, types.DynType),
				cel.FunctionBinding(functions.Diff),
			),
			cel.MemberOverload(
				"node_diff_ids",
				[]*cel.Type{elements.NodeType, elements.NodeType, types.BoolType},
				types.NewMapType(types.StringType, types.DynType),
				cel.FunctionBinding(functions.Diff),
			),
		),
		// intersect returns a new nodelist with the nodes and relationships
		// common to both operands.
		cel.Function(
			"intersect",
			cel.MemberOverload(
				"nodelist_intersect",
				[]*cel.Type{elements.NodeListType, elements.NodeListType},
				elements.NodeListType,
				cel.BinaryBinding(functions.Intersect),
			),
		),
		// get_node_graph returns the full graph of the node with the given
		// ID.
		cel.Function(
			"get_node_graph",
			cel.MemberOverload(
				"nodelist_node_graph",
				[]*cel.Type{elements.NodeListType, types.StringType},
				elements.NodeListType,
				cel.BinaryBinding(functions.NodeGraph),
			),
		),
		// get_node_siblings returns the fragment with the immediate
		// siblings of the node with the given ID.
		cel.Function(
			"get_node_siblings",
			cel.MemberOverload(
				"nodelist_node_siblings",
				[]*cel.Type{elements.NodeListType, types.StringType},
				elements.NodeListType,
				cel.BinaryBinding(functions.NodeSiblings),
			),
		),
		// get_nodes_by_identifier returns the nodes carrying an identifier
		// of the named type with the given value.
		cel.Function(
			"get_nodes_by_identifier",
			cel.MemberOverload(
				"nodelist_nodes_by_identifier",
				[]*cel.Type{elements.NodeListType, types.StringType, types.StringType},
				types.NewListType(elements.NodeType),
				cel.FunctionBinding(functions.GetNodesByIdentifier),
			),
		),
		// get_matching_node looks up the node describing the same software
		// as the provided node, matching by hashes and package URL.
		cel.Function(
			"get_matching_node",
			cel.MemberOverload(
				"nodelist_matching_node",
				[]*cel.Type{elements.NodeListType, elements.NodeType},
				elements.NodeType,
				cel.BinaryBinding(functions.GetMatchingNode),
			),
		),
		// get_purl returns the package URL of a node as a string.
		cel.Function(
			"get_purl",
			cel.MemberOverload(
				"node_get_purl",
				[]*cel.Type{elements.NodeType},
				types.StringType,
				cel.UnaryBinding(functions.NodeGetPurl),
			),
		),
	}

	// Here we add all the functions that trigger I/O calls on the host system
	// only if the option is enables. Most apps will not need them so we don't
	// load them by default.
	if p.Options.EnableIO {
		envopt = append(
			envopt,
			cel.Function(
				"load_sbom",
				cel.MemberOverload(
					"protobom_loadsbom_binding",
					[]*cel.Type{elements.ProtobomType, cel.StringType}, elements.DocumentType,
					cel.BinaryBinding(functions.LoadSBOM),
				),
			),
		)
	}
	return envopt
}
