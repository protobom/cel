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
func (*Protobom) Functions() []cel.EnvOption {
	return []cel.EnvOption{
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
				"enodelist_get_nodes", []*cel.Type{cel.ObjectType("protobom.protobom.NodeList")}, types.NewListType(types.DynType),
				cel.UnaryBinding(functions.NodeListGetNodes),
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
			"load_sbom",
			cel.MemberOverload(
				"protobom_loadsbom_binding",
				[]*cel.Type{elements.ProtobomType, cel.StringType}, elements.DocumentType,
				cel.BinaryBinding(functions.LoadSBOM),
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
				elements.DocumentType, // result
				cel.FunctionBinding(functions.RelateNodeListAtID),
			),
		),
		cel.Function(
			"get_authors",
			cel.MemberOverload(
				"sbom_get_authors",
				[]*cel.Type{elements.DocumentType},
				types.ListType, // result
				cel.UnaryBinding(functions.DocumentAuthors),
			),
			cel.MemberOverload(
				"metadata_get_authors",
				[]*cel.Type{elements.MetadataType},
				types.ListType, // result
				cel.UnaryBinding(functions.DocumentAuthors),
			),
		),
	}
}
