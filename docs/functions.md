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
| `get_nodes_by_identifier(type, value)` | string, string | list of Node | Returns the nodes carrying an identifier of the named type (`"purl"`, `"cpe23"`, ...) with the given value | — | ✔️ | — |
| `get_matching_node(node)` | Node | Node | Returns the node describing the same software as the provided node, matching by hashes and package URL. Evaluates to `null` when nothing matches and errors when more than one node does | — | ✔️ | — |
| `get_node_descendants(id, depth)` | string, int | NodeList | Returns the graph fragment starting at a node, down to the given depth | — | ✔️ | — |
| `get_node_ancestors(id, depth)` | string, int | NodeList | Returns the graph fragment with the elements pointing to a node, up to the given depth | — | ✔️ | — |
| `get_node_graph(id)` | string | NodeList | Returns the full graph of the node with the given identifier | — | ✔️ | — |
| `get_node_siblings(id)` | string | NodeList | Returns the fragment with the immediate siblings of the node with the given identifier | — | ✔️ | — |
| `get_edges_from(id)` | string | list of Edge | Returns the edges originating at the node with the given identifier | — | ✔️ | — |
| `get_edges_to(id)` | string | list of Edge | Returns the edges pointing to the node with the given identifier | — | ✔️ | — |
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
| `get_purl()` | — | string | Returns the package URL of a node. Nodes without one, files among them, evaluate to an empty string | — | — | ✔️ | — |

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
| `add(nodelist)` | NodeList | NodeList | Returns the union of both node lists | — | ✔️ | — |
| `intersect(nodelist)` | NodeList | NodeList | Returns the nodes and relationships common to both node lists | — | ✔️ | — |
| `relate_node_list_at_id(nodelist, id, type)` | NodeList, string, string | same as receiver | Relates the nodes of a NodeList to the node with the given identifier through a relationship of the named type | ✔️ | ✔️ | — |
| `unrelate_nodes(from, to, type)` | string, string, string | NodeList | Removes the relationship of the named type between two nodes. Other destinations of the same relation are preserved | — | ✔️ | — |
| `remove_edges_from(id, type)` | string, string | NodeList | Removes all the relationships of the named type originating at a node | — | ✔️ | — |

Relationship types are named by their protobom identifiers, such as
`"dependsOn"` or `"contains"`. The match ignores case and underscores, so
SPDX-style spellings like `"DEPENDS_ON"` name the same type; a name that
matches no type is an evaluation error. All of these functions keep CEL
value semantics: the element they are invoked on is never modified, the
result is a new element with the change applied.

⚠️ Known limitation: the Document overload of `to_document()` is registered
but currently fails at evaluation time.

## Diffing

| Function | Arguments | Returns | Description | Document | NodeList | Node |
| --- | --- | --- | --- | --- | --- | --- |
| `diff(other)` | same type as receiver | map | Compares two elements and returns a map describing the changes that transform the receiver into the argument | ✔️ | ✔️ | ✔️ |
| `diff(other, with_ids)` | same type, bool | map | Same, counting identifier changes as changes when the flag is true | ✔️ | ✔️ | ✔️ |

Following the protobom diff semantics, identifiers are used to pair the
nodes of the two elements but their changes do not count as changes unless
the flag is passed.

Every report carries a `count` entry totaling the changes, so two
equivalent elements produce `{"count": 0}` and expressions can gate on the
count without null checks:

```javascript
sboms[0].diff(sboms[1]).count == 0
```

A nodelist report also carries `added`, `removed` and `modified` (the
modified entries are maps with `before`, `after`, `added`, `removed` and
`count`), the `edges_added` and `edges_removed` deltas, and
`root_elements_added` and `root_elements_removed`. A document report nests
a `metadata` and a `nodelist` report, present only when they carry changes.
A node report carries `added` and `removed` nodes populated with the fields
that changed.

## I/O Functions

Functions that read from the host filesystem are not registered by default.
To enable them, configure the library with the `EnableIO` option:

```golang
library.NewProtobom(library.WithEnableIO(true))
```

| Function | Arguments | Returns | Description | Receiver |
| --- | --- | --- | --- | --- |
| `load_sbom(path)` | string | Document | Parses an SBOM file (SPDX or CycloneDX) and returns it as a Document | `protobom` |
