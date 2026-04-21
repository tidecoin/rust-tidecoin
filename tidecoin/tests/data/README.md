# Test vector data

This directory contains test vector data used by the Tidecoin crate.

Consumers must treat each file according to its local test comments. Some data
is Tidecoin-node parity material; some data is generic codec or algorithm
coverage retained only because the binary format is protocol-compatible.

`node_policy_provenance_corpus.json` is generated, not hand-edited.

Refresh it against the current Tidecoin node checkout with:

```bash
python3 tidecoin/contrib/generate_node_policy_provenance_corpus.py \
  --node-repo /path/to/tidecoin
```

Then validate it with:

```bash
TIDECOIN_NODE_REPO=/path/to/tidecoin \
cargo test -p tidecoin --test node_policy_provenance -- --nocapture
```
