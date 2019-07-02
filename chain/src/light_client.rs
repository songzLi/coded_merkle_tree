use ser::{deserialize, serialize};
use {BlockHeader, Transaction};
use constants::{BASE_SYMBOL_SIZE, AGGREGATE, RATE, SAMPLE_COMPLEXITY};
use {Symbols, SymbolBase, SymbolUp};
use bytes::Bytes;
use coded_merkle_roots::coded_merkle_roots;
use hash::H256;
use merkle_root::merkle_root;
use rand::distributions::{Distribution, Uniform};

#[derive(Debug, PartialEq, Clone, Serializable, Deserializable)]
pub struct LightClient {
	pub block_header: BlockHeader,
}

impl LightClient {
	// We have n coded symbols in the block, and each light node randomly samples s of them
	pub fn sampling_base(&self, n: u64, s: u32) -> (Vec<u64>, Vec<SymbolBase>, Vec<Vec<SymbolUp>>) {
		let k = ((n as f32) * RATE) as u32; //number of systematic symbols on the base layer

		let mut index = vec![];//indices of sampled symbols
		let mut symbols: Vec<SymbolBase> = vec![];//sampled symbols
		let mut proofs: Vec<Vec<SymbolUp>> = vec![];//Merkle proofs of sampled symbols

		let mut rng = rand::thread_rng();
        let die = Uniform::from(0..n);

        //sample the first symbol
		let throw = die.sample(&mut rng); //select the first index of the coded symbol to sample
		let (symbol, proof): (Option<SymbolBase>, Option<Vec<SymbolUp>>) = 
		match (symbol, proof) {
			(None, _) => panic!("Symbol No.{} is missing!", throw),
			(_, None) => panic!("Merkle proof for symbol No.{} is missing!", throw),
			(Some(s), Some(p)) => {
				if self.block_header.verify_base(s, throw, k, &p) {
					index.push(throw);
					symbols.push(s);
					proofs.push(p);
				} else {
					panic!("Merkle proof for symbol No.{} does not pass!", throw);
				}
			},
		}

		for _ in 1..s {
			let throw = die.sample(&mut rng);
			if !index.contains(&throw) {
				let (symbol, proof): (Option<SymbolBase>, Option<Vec<SymbolUp>>) = 
				match (symbol, proof) {
					(None, _) => panic!("Symbol No.{} is missing!", throw),
					(_, None) => panic!("Merkle proof for symbol No.{} is missing!", throw),
					(Some(s), Some(p)) => {
						if self.block_header.verify_base(s, throw, k, &p) {
					        index.push(throw);
					        symbols.push(s);
					        proofs.push(p);
					    } else {
					        panic!("Merkle proof for symbol No.{} does not pass!", throw);
					    }
					},
				}
			}
		}

		(index, symbols, proofs)
	}
}