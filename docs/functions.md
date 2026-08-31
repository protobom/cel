# Protobom CEL Function Reference

This document lists the functions that the protobom CEL library registers in
the CEL environment. The authoritative definitions live in
[`pkg/library/api.go`](../pkg/library/api.go).

All functions use CEL member call syntax, that is, they are invoked on a
receiver element:

```javascript
sboms[0].get_packages().to_document()
```

The receiver columns in the tables below show which element types each
function can be invoked on.

## Variables

Programs evaluated with the bundled [runner](../pkg/runner) have two
predefined variables in scope:

| Variable | Type | Description |
| --- | --- | --- |
| `sboms` | list of Document | The SBOMs loaded into the environment, in the order they were passed to `runner.BuildVariables()`. |
| `protobom` | Protobom | Global object hosting the functions not bound to a document element, such as `load_sbom()`. |

Both variable names can be customized when configuring the library with
`library.WithDocsVarName()` and `library.WithProtobomVarName()`.

## Querying Functions

| Function | Arguments | Returns | Description | Document | NodeList | Node |
| --- | --- | --- | --- | --- | --- | --- |
| `get_files()` | — | NodeList | Returns the nodes describing files | ✔️ | ✔️ | ✔️ |
| `get_packages()` | — | NodeList | Returns the nodes describing packages | ✔️ | ✔️ | ✔️ |
| `get_node_by_id(id)` | string | Node | Returns the node with the matching identifier | ✔️ | ✔️ | — |
| `get_nodes_by_name(name)` | string | list of Node | Returns all nodes whose name matches | — | ✔️ | — |
| `get_nodes_by_purl_type(type)` | string | NodeList | Returns all nodes whose package URL is of the given type | ✔️ | ✔️ | — |
| `get_node_descendants(id, depth)` | string, int | NodeList | Returns the graph fragment starting at a node, down to the given depth | — | ✔️ | — |
| `get_root_nodes()` | — | list of Node | Returns the root nodes of the graph | ✔️ | ✔️ | — |

## Data Accessors

| Function | Arguments | Returns | Description | Document | NodeList | Node | Metadata |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get_node_list()` | — | NodeList | Returns the document's node list | ✔️ | — | — | — |
| `get_metadata()` | — | Metadata | Returns the document's metadata | ✔️ | — | — | — |
| `get_nodes()` | — | list of Node | Returns the nodes of the node list | — | ✔️ | — | — |
| `get_edges()` | — | list of Edge | Returns the edges of the node list | — | ✔️ | — | — |
| `get_authors()` | — | list of Person | Returns the document authors | ✔️ | — | — | ✔️ |
| `get_suppliers()` | — | list of Person | Returns the persons acting as suppliers of a node | — | — | ✔️ | — |
| `get_originators()` | — | list of Person | Returns the persons acting as originators of a node | — | — | ✔️ | — |

In addition to these functions, the wrapped protobom elements expose their
fields directly to CEL programs using the protobuf field names, for example:

```javascript
sboms[0].metadata.name
sboms[0].node_list.get_root_nodes()[0].name
```

## Transformation and Composition Functions

| Function | Arguments | Returns | Description | Document | NodeList | Node |
| --- | --- | --- | --- | --- | --- | --- |
| `to_node_list()` | — | NodeList | Wraps the element into a NodeList | ✔️ | ✔️ | ✔️ |
| `to_document()` | — | Document | Wraps the element into a new Document | ⚠️ | ✔️ | ✔️ |
| `add(nodelist)` | NodeList | NodeList | Combines two node lists into one | — | ⚠️ | — |
| `relate_node_list_at_id(nodelist, id, type)` | NodeList, string, string | Document | Relates the nodes of a NodeList to the node with the given identifier | ✔️ | ✔️ | — |

⚠️ Known limitations:

- The Document overload of `to_document()` is registered but currently fails
  at evaluation time.
- `add()` is not implemented yet: it is registered but returns an empty
  NodeList.
- `relate_node_list_at_id()` accepts a relationship type string but currently
  ignores it, always creating relationships of type `DEPENDS_ON`. When invoked
  on a NodeList (instead of a Document), it returns the modified NodeList.

## I/O Functions

Functions that read from the host filesystem are not registered by default.
To enable them, configure the library with the `EnableIO` option:

```golang
library.NewProtobom(library.WithEnableIO(true))
```

| Function | Arguments | Returns | Description | Receiver |
| --- | --- | --- | --- | --- |
| `load_sbom(path)` | string | Document | Parses an SBOM file (SPDX or CycloneDX) and returns it as a Document | `protobom` |
