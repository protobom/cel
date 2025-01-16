# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright 2025 The Protobom Authors

## Tests
.PHONY: test
test:
	go test -v ./...

.PHONY: sbom
sbom:
	cd dist && bom generate -c ../.bom.yaml -o sbom.spdx.json --format=json

