package functions

import (
	"github.com/bom-squad/protobom/pkg/sbom"
	"github.com/chainguard-dev/bomshell/pkg/elements"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NodeToNodeList takes a node and returns a new NodeList
// with that nodelist with the node as the only member.
var NodeToNodeList = func(lhs ref.Val) ref.Val {
	var node elements.Node
	var ok bool
	if node, ok = lhs.(elements.Node); !ok {
		return types.NewErr("attemtp to convert a non node")
	}
	return node.ToNodeList()
}

var Addition = func(lhs, rhs ref.Val) ref.Val {
	return elements.NodeList{
		NodeList: &sbom.NodeList{},
	}
}

var AdditionOp = func(vals ...ref.Val) ref.Val {
	return elements.NodeList{
		NodeList: &sbom.NodeList{},
	}
}

// ElementById returns a Node matching with the specified ID
var NodeById = func(lhs, rawID ref.Val) ref.Val {
	queryID, ok := rawID.Value().(string)
	if !ok {
		return types.NewErr("argument to element by id has to be a string")
	}

	bom, ok := lhs.Value().(*sbom.Document)
	if !ok {
		return types.NewErr("unable to convert sbom to native (wrong type?)")
	}
	node := bom.NodeList.GetNodeByID(queryID)
	// Perhaps we shouls thrown an error here.
	if node == nil {
		return nil
	}

	return elements.Node{
		Node: node,
	}
}

var Files = func(lhs ref.Val) ref.Val {
	nl := elements.NodeList{
		NodeList: &sbom.NodeList{},
	}
	bom, ok := lhs.Value().(*sbom.Document)
	if !ok {
		return types.NewErr("unable to convert sbom to native (wrong type?)")
	}
	nl.Edges = bom.NodeList.Edges
	for _, n := range bom.NodeList.Nodes {
		if n.Type == sbom.Node_FILE {
			nl.NodeList.Nodes = append(nl.NodeList.Nodes, n)
		}
	}
	cleanEdges(&nl)
	return nl
}

var Packages = func(lhs ref.Val) ref.Val {
	nl := elements.NodeList{
		NodeList: &sbom.NodeList{},
	}
	bom, ok := lhs.Value().(*sbom.Document)
	if !ok {
		return types.NewErr("unable to convert sbom to native (wrong type?)")
	}
	nl.Edges = bom.NodeList.Edges
	for _, n := range bom.NodeList.Nodes {
		if n.Type == sbom.Node_PACKAGE {
			nl.NodeList.Nodes = append(nl.NodeList.Nodes, n)
		}
	}
	cleanEdges(&nl)
	return nl
}

var ToDocument = func(lhs, rhs ref.Val) ref.Val {
	nl, ok := lhs.Value().(*sbom.NodeList)
	if !ok {
		return types.NewErr("documents can be created only from nodelists")
	}
	return elements.Document{
		Document: &sbom.Document{
			Metadata: &sbom.Metadata{
				Id:      "",
				Version: "",
				Name:    "",
				Date:    timestamppb.Now(),
				Tools:   []*sbom.Tool{},
				Authors: []*sbom.Person{},
				Comment: "",
			},
			NodeList: nl,
		},
	}

}
