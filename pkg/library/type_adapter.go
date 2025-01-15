package library

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/protobom/cel/pkg/elements"
)

type TypeAdapter struct{}

func (TypeAdapter) NativeToValue(value interface{}) ref.Val {
	val, ok := value.(elements.Bomshell)
	if ok {
		return val
	} else {
		// let the default adapter handle other cases
		return types.DefaultTypeAdapter.NativeToValue(value)
	}
}
