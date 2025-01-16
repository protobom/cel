// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

package library

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/protobom/cel/pkg/elements"
)

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value any) ref.Val {
	val, ok := value.(elements.Protobom)
	if ok {
		return &val
	}
	// let the default adapter handle other cases
	return types.DefaultTypeAdapter.NativeToValue(value)
}
