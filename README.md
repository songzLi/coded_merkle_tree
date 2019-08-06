# Coded Merkle Tree

In this package, we implement _coded Merkle tree_ (CMT) for Parity Bitcoin client. The main functionalities of constructing and decoding a CMT are implemented in the chain crate. 

## Tests (chain/src/main.rs)
Run `cargo run` to test our coded Merkle tree (CMT) library using parmeters from reference designs.

A reference design specifies:
1. Blocksize(size of transactions), and symbol size on the base layer, hence we know # of systematic symbols k.
2. Number of hashes to aggregate on higher layer of CMT
3. Number of hashes in the block header.
4. All codes on all levels of CMT

For each reference, we have the following two tests:
1. Stopping set test: randomly sample a subset of symbols on each layer of CMT, and see if we can decode the entire tree.
2. Incorrect-coding test: flip the bits of parity symbols after encoding, and use flipped symbols to construct CMT. Check if the decoder correctly generates the incorrect-coding proof.
