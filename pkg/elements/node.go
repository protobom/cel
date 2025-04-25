// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package elements

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/protobom/protobom/pkg/sbom"
)

var (
	NodeObject = decls.NewObjectType("protobom.protobom.Node")
	NodeType   = cel.ObjectType("protobom.protobom.Node")
)

type Node struct {
	*sbom.Node
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (n *Node) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeOf(n).AssignableTo(typeDesc) {
		return n, nil
	} else if reflect.TypeOf(n.Node).AssignableTo(typeDesc) {
		return n.Node, nil
	}

	return nil, fmt.Errorf("type conversion error from 'Node' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (n *Node) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case NodeType:
		return n
	case types.TypeType:
		return NodeType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", NodeType, typeVal)
}

// Equal implements ref.Val.Equal.
func (n *Node) Equal(other ref.Val) ref.Val {
	otherNode, ok := other.(*Node)
	if !ok {
		return types.MaybeNoSuchOverloadErr(other)
	}

	if n.Node.Equal(otherNode.Node) {
		return types.True
	}
	return types.False
}

func (*Node) Type() ref.Type {
	return NodeType
}

// Value implements ref.Val.Value.
func (n *Node) Value() any {
	return n.Node
}

// ToNodeList returns a new NodeList with the node as the only member
func (n *Node) ToNodeList() *NodeList {
	return &NodeList{
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{n.Node},
			Edges:        []*sbom.Edge{},
			RootElements: []string{n.Id},
		},
	}
}

var _ traits.Indexer = (*Node)(nil)

//nolint:gocyclo
func (n *Node) Get(index ref.Val) ref.Val {
	switch v := index.Value().(type) {
	case string:
		switch v {
		case "id":
			return types.String(n.Id)
		case propName:
			return types.String(n.Name)
		case propType:
			return types.String(n.Node.Type.String())
		case propVersion:
			return types.String(n.Version)
		case "file_name":
			return types.String(n.FileName)
		case "url_home":
			return types.String(n.UrlHome)
		case "url_download":
			return types.String(n.UrlDownload)
		case "licenses":
			return types.NewDynamicList(types.DefaultTypeAdapter, n.Licenses)
		case "license_concluded":
			return types.String(n.LicenseConcluded)
		case "license_comments":
			return types.String(n.LicenseComments)
		case "copyright":
			return types.String(n.Copyright)
		case "source_info":
			return types.String(n.SourceInfo)
		case propComment:
			return types.String(n.Comment)
		case "summary":
			return types.String(n.Summary)
		case "description":
			return types.String(n.Description)
		case "attribution":
			return types.NewDynamicList(types.DefaultTypeAdapter, n.Attribution)
		case "suppliers":
			personsList := []ref.Val{}
			for _, person := range n.Suppliers {
				p := &Person{
					Person: person,
				}
				personsList = append(personsList, p)
			}
			return types.NewRefValList(types.DefaultTypeAdapter, personsList)

		case "originators":
			personsList := []ref.Val{}
			for _, person := range n.Originators {
				p := &Person{
					Person: person,
				}
				personsList = append(personsList, p)
			}
			return types.NewRefValList(types.DefaultTypeAdapter, personsList)
		case "release_date":
			return types.Timestamp{Time: n.ReleaseDate.AsTime()}
		case "build_date":
			return types.Timestamp{Time: n.BuildDate.AsTime()}
		case "valid_until_date":
			return types.Timestamp{Time: n.ValidUntilDate.AsTime()}
		case "external_references":
			return types.NewDynamicList(types.DefaultTypeAdapter, n.ExternalReferences)
		case "file_types":
			return types.NewDynamicList(types.DefaultTypeAdapter, n.FileTypes)
		case "identifiers":
			ret := map[string]string{}
			for t, v := range n.Identifiers {
				if _, ok := sbom.SoftwareIdentifierType_name[t]; ok {
					ret[sbom.SoftwareIdentifierType_name[t]] = v
				} else {
					ret[sbom.SoftwareIdentifierType_name[0]] = v
				}
			}
			return types.NewDynamicMap(types.DefaultTypeAdapter, ret)
		case propHashes:
			ret := map[string]string{}
			for a, v := range n.Hashes {
				if _, ok := sbom.HashAlgorithm_name[a]; ok {
					ret[sbom.HashAlgorithm_name[a]] = v
				} else {
					ret[sbom.HashAlgorithm_name[0]] = v
				}
			}
			return types.NewDynamicMap(types.DefaultTypeAdapter, ret)
		case "primary_purpose":
			ret := []string{}
			for _, p := range n.PrimaryPurpose {
				ret = append(ret, p.String())
			}
			return types.NewDynamicList(types.DefaultTypeAdapter, ret)
		case "properties":
			return types.NewDynamicList(types.DefaultTypeAdapter, n.Properties)
		default:
			return types.NewErr("no such key %v", index)
		}
	default:
		return types.NewErr("no such key %v", index)
	}
}
