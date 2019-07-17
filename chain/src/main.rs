extern crate rustc_hex as hex;
extern crate heapsize;
extern crate primitives;
extern crate rayon;
extern crate bitcrypto as crypto;
extern crate serialization as ser;
extern crate rand;
extern crate chain;

#[macro_use]
extern crate serialization_derive;

use primitives::{hash, bytes, bigint, compact};
use ser::{deserialize, serialize};
use bytes::Bytes;
use hash::H256;
use rand::distributions::{Distribution, Bernoulli, Uniform};

use chain::block_header::BlockHeader;
use chain::transaction::{Transaction, TransactionInput, TransactionOutput, OutPoint};
use chain::constants::{BASE_SYMBOL_SIZE, AGGREGATE, RATE, HEADER_SIZE};
use chain::coded_merkle_roots::{Symbols, SymbolBase, SymbolUp, coded_merkle_roots};
use chain::merkle_root::merkle_root;
use chain::decoder::{Code, Symbol};


fn main() {
	//Test 1: 
	println!("Test.");

	//Test 2:

}