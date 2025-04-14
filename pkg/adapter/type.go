// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package adapter

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/protobom/protobom/pkg/sbom"

	"github.com/protobom/cel/pkg/elements"
)

// The Protobom TypeAdapter converts native protobom elements resulting from
// the graph API operations or evaluations into their CEL-friendly wrappers
// that implenent ref.Val
type ProtobomTypeAdapter struct{}

// NativeToValue converts from the native protobom elements to their elements.*
// wrappers so that they can be handled in the CEL environment.
func (ProtobomTypeAdapter) NativeToValue(value any) ref.Val {
	switch v := value.(type) {
	case elements.Protobom:
		return &v
	// Actual types:
	case sbom.Document:
		return &elements.Document{Document: &v}
	case sbom.NodeList:
		return &elements.NodeList{NodeList: &v}
	case sbom.Node:
		return &elements.Node{Node: &v}
	case sbom.Person:
		return &elements.Person{Person: &v}
	// Pointers:
	case *sbom.Document:
		return &elements.Document{Document: v}
	case *sbom.NodeList:
		return &elements.NodeList{NodeList: v}
	case *sbom.Node:
		return &elements.Node{Node: v}
	case *sbom.Person:
		return &elements.Person{Person: v}
	}

	// let the default adapter handle other cases
	return types.DefaultTypeAdapter.NativeToValue(value)
}
