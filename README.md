# Protobom CEL Integration

This repository houses the protobom CEL integration. This is a go module that
can be embedded in other programs that wish to let users query and recompose
SBOM data based on the [Common Expression Language](https://cel.dev/) (CEL).

This project provides the functions and data types to expose the protobom graph
API to the CEL evaluator.

## Example

The easiest way to embed the integration is through the `runner` package. A
runner wraps a CEL environment preloaded with the protobom library, letting
your users query SBOMs and remix their data using simple CEL expressions:

```golang
package main

import (
	"os"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"

	"github.com/protobom/cel/pkg/runner"
)

func main() {
	// Create a new runner with the default options:
	r, err := runner.NewRunner()
	if err != nil {
		panic(err)
	}

	// Build the variables map exposed to the CEL program. Here we
	// parse an SBOM from disk and expose it in the `sboms` list:
	vars, err := runner.BuildVariables(
		runner.WithPaths([]string{"examples/curl.spdx.json"}),
	)
	if err != nil {
		panic(err)
	}

	// Evaluate a CEL program: extract all packages from the SBOM
	// and recompose them into a new document:
	result, err := r.Evaluate(`sboms[0].get_packages().to_document()`, vars)
	if err != nil {
		panic(err)
	}

	doc, ok := result.Value().(*sbom.Document)
	if !ok {
		panic("expected the program to return a document")
	}

	// Write the resulting SBOM to STDOUT as CycloneDX 1.6:
	w := writer.New(writer.WithFormat(formats.CDX16JSON))
	if err := w.WriteStream(doc, os.Stdout); err != nil {
		panic(err)
	}
}
```

Running this program parses the SPDX example SBOM, drops everything but its
packages, and prints the result as a new CycloneDX document. The functions
available to CEL programs are described in [docs/functions.md](docs/functions.md)
and there are more sample CEL programs in the [examples](examples) directory.

## Contributing

Contributions are welcome!

## Documentation

Check out the [function reference](docs/functions.md) and the collection of
[example CEL programs](examples).

## History

Part of the [Protobom](https://github.com/protobom) ecosystem. This project was
originally funded by the
[DHS Science and Technology](https://www.dhs.gov/science-and-technology) directorate.

