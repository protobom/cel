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
	return []cel.EnvOption{
		cel.Function(
			"files",
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
			"packages",
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
			"ToNodeList",
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
			"NodeByID",
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
			"NodesByPurlType",
			cel.MemberOverload(
				"sbom_nodesbypurltype_binding", []*cel.Type{elements.DocumentType, cel.StringType}, elements.NodeListType,
				cel.BinaryBinding(functions.NodesByPurlType),
			),
			cel.MemberOverload(
				"nodelist_nodesbypurltype_binding", []*cel.Type{elements.NodeListType, cel.StringType}, elements.NodeListType,
				cel.BinaryBinding(functions.NodesByPurlType),
			),
		),

		// ToDocument wraps an element and returns a new Document
		// Overloaded in: Node NodeList and Document (noop)
		cel.Function(
			"ToDocument",
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
			"LoadSBOM",
			cel.MemberOverload(
				"bomshell_loadsbom_binding",
				[]*cel.Type{elements.BomshellType, cel.StringType}, elements.DocumentType,
				cel.BinaryBinding(functions.LoadSBOM),
			),
		),

		cel.Function(
			"RelateNodeListAtID",
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
	}
}
