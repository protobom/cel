// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

// Package elements has wrappers of the protobom elements (from the
// main protobuf definition) that implement the ref.Val interface
// used by the CEL runtime. This lets the library expose them natively
// in the CEL evaluation environment.
//
// As of v0.1.0 the elements package has a complete wrappers library
// for the native elements defined in protobom v0.5.x.
package elements

// Constants for common property names
const (
	propType    = "type"
	propHashes  = "hashes"
	propComment = "comment"
	propName    = "name"
	propVersion = "version"
)
