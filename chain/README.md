# Chain for Coded Merkle Tree

In this crate, we implement _coded Merkle tree_ (CMT) for Parity Bitcoin blocks.

## Overview
We add the following modules to impplement CMT.
* Coded Merkle Roots
* Decoder

We modify the following modules of parity Bitcoin block to reflect the addition of CMT.
* Block 
* Block Header

## Crate Content

### Coded Merkle Tree (coded_merkle_roots.rs)
Transactions in a block are serialized and partitioned into symbols with type `SymbolBase`. Encode k base symbols to generate n coded symbols. We use systematic codes such that the first k coded symbols are the original data symbols. This forms the first layer of CMT.

To construct the next layer of CMT, we 
1. Compute the hashes of the coded symbols on the base layer.
2. Aggregate `AGGREGATE` hashes using `hash_aggregate` into multiple symbols of type `SymbolUp`
3. Encode these symbols using the code for this layer
Repeat this process until the number of coded symbols in a layer is as small as `header_size`. 

``` rust
pub fn coded_merkle_roots(symbols: &[SymbolBase], header_size: u32, rate: f32, codes: Vec<Code>, correct: Vec<bool>) 
-> (Vec<H256>, Vec<Symbols>)
```
constructs a CMT for a block from `symbols` which are transactions of the block.
* `header_size` indicates the number of symbols on the last layer of CMT
* `rate` is the coding rate
* `codes` is a vector of LDPC codes used for all layers of CMT
* `correct` indicates if we perform the encoding correctly according to `codes`. Used for tests.
*  Output contains the hashes of the symbols on the last layer, and the CMT itself 

### Decoder (decoder.rs)
This module implements decoding/encoding symbols on CMT using peeling decoder for LDPC codes.

Decoder for CMT: 
``` rust
pub struct TreeDecoder {
	pub n: u64, //block length of code on the base layer of the tree
	pub height: u32, 
	pub decoders: Vec<Decoder>, 
	pub hashes: Vec<Vec<H256>> //hashes of all layers
}
```
Decoder for a single layer of CMT:
``` rust
pub struct Decoder {
	pub level: u32, // layer index of CMT
	pub n: u64, // # of coded symbols
	pub k: u64, // # of systematic symbols
	pub p: u64, // # of parity check equations

	pub code: Code, //code shall not change during decoding

	pub parities: Vec<Vec<u64>>, // vector of length p, each element is a vector indicating the variable nodes connected to a parity node
	pub symbols: Vec<Vec<u64>>, // vector of length n, each element is a vector indicating the parity nodes connected to a variable node

	pub symbol_values: Vec<Symbol>, // values of variable nodes
        pub parity_values: Vec<Symbol>, //values of parity nodes
        pub parity_degree: Vec<u32>, 
        pub degree_1_parities: Vec<u64>, // set of parity nodes whose degree is 1 during decoding

        pub num_decoded_sys_symbols: u64,
        pub num_decoded_symbols: u64,
}
```
`symbol_update_from_reception`, `parity_update`, and `symbol_update_from_degree_1_parities` together implement the peeling decoder, which iteratively decode symbols from degree-1 parity equations.

`run_tree_decoder` decodes the CMT from the top layer to the base layer. The decoding of each layer is hash protected. Once decoded, the systematic symbols on a layer is used as the hashes of the coded symbols on the previous layer. Using these hash values, the following three coding errors can be detected by the decoder:
``` rust
pub enum CodingErr{
	NotZero, // symbols in a parity equation does not sum up to zero
	NotHash, // decoded symbol does not match its hash
	Stopped, // peeling decoder cannot continue due to absence of degree-one parity node 
} 
```
Once detecting one of these errors, decoder constrcuts a `IncorrectCodingProof`.

Encoding is done by feeding original symbols into peeling decoder.

### Block (block.rs)
Add a function `coded_merkle_roots` to construct CMT and its root hashes from transactions in the block.

Now include the CMT in the block:
```rust 
pub struct Block {
	pub block_header: BlockHeader,
	pub transactions: Vec<Transaction>,
	pub coded_tree: Vec<Symbols>, //Coded Merkle tree constructed from the transactions in the block
	pub block_size_in_bytes: usize, // size of transactions in the block, used to specify block size for tests
}
```

Implement the Merkle proof of a symbol in the CMT in `merkle_proof`. Returned is a vector of symbols (and their respective indices), each of which is from a layer above the current layer.

### Block Header (block_header.rs)
Now include the root hashes of CMT in the header:
```rust
pub struct BlockHeader {
	pub version: u32,
	pub previous_header_hash: H256,
	pub merkle_root_hash: H256,
	pub time: u32,
	pub bits: Compact,
	pub nonce: u32,
	pub coded_merkle_roots_hashes: Vec<H256>,//hashes of the symbols on the top layer of coded Merkle tree
}
```
Add functions `verify_up` and `verify_base` to verify Merkle proof of a symbol in the CMT. 


### Constants (constants.rs)
* `BLOCK_SIZE`: size of the transactions in a block
* `BASE_SYMBOL_SIZE`: size of a symbol on the base layer in bytes
* `AGGREGATE`: number of hashes to aggregate to form a new symbol on the upper layers of CMT
* `RATE`: coding rate for code ensemble
* `HEADER_SIZE`: number of hashes of coded symbols stored in the block header 
* `NUMBER_ITERATION`: number of times to sample the base symbols of the CMT (for tests)


### Tests (main.rs)
We test our coded Merkle tree (CMT) library using parmeters from reference designs.

A reference design specifies:
1. Blocksize(size of transactions), and symbol size on the base layer, hence we know # of systematic symbols k.
2. Number of hashes to aggregate on higher layer of CMT
3. Number of hashes in the block header.
4. All codes on all levels of CMT

For each reference, we have the following two tests:
1. Stopping set test: randomly sample a subset of symbols on each layer of CMT, and see if we can decode the entire tree.
2. Incorrect-coding test: flip the bits of parity symbols after encoding, and use flipped symbols to construct CMT. Check if the decoder correctly generates the incorrect-coding proof.

#### Reference LDPC codes
Various reference LDPC codes are included in the LDPC_codes folder. Each code has a encode file and a decode file.

