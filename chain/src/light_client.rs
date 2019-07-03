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
			//if !index.contains(&throw) {
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
			//}
		}

		(index, symbols, proofs)
	}

    //Take s samples from each upper layer of coded Merkle tree
	pub fn sampling_upper(&self, index: Vec<u64>, proofs: Vec<Vec<SymbolUp>>, s: u32) -> (Vec<Vec<u64>>, 
		Vec<Vec<SymbolUp>>, Vec<Vec<Option<Vec<SymbolUp>>>>) {
		let height = proofs[0].len() + 1; //height of coded Merkle tree
		for j in 0..s { //iterate over s samples
			for i in 1..height {  //iterate over height - 1 upper layers
				let mut symbol: SymbolUp = proofs[j][i - 1];
				if i < height - 1 {
				    let mut proof: Option<Vec<SymbolUp>> = Some(proofs[j][i..(height - 1)].to_vec());
				} else {
					let mut proof: Option<Vec<SymbolUp>> = None;
				}
	

			} 

		}


	}






}