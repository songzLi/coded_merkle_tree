use hex::FromHex;
//use ser::{deserialize};
use ser::{deserialize, serialize};
use {BlockHeader, Transaction};
use constants::{BASE_SYMBOL_SIZE, AGGREGATE, RATE};
use {Symbols, SymbolBase, SymbolUp};
use bytes::Bytes;
use coded_merkle_roots::coded_merkle_roots;
use hash::H256;
use merkle_root::merkle_root;
use decoder::Code;

#[derive(Debug, PartialEq, Clone, Serializable, Deserializable)]
pub struct Block {
	pub block_header: BlockHeader,
	pub transactions: Vec<Transaction>,
}

//a new type for a coding errors
pub enum CodingErr{
	NotZero,
	NotHash,
} 


pub fn next_index(index: u32, k: u32, reduce_factor: u32) -> u32 {
	if index <= k - 1 {
		index / reduce_factor
	}
	else {
		(index - k) / ((AGGREGATE as u32) - reduce_factor)
	}
}

// pub fn next_index<T>(index: T, k: T, reduce_factor: T) -> T {
// 	if index <= k - 1 {
// 		index / reduce_factor
// 	}
// 	else {
// 		(index - k) / ((AGGREGATE as T) - reduce_factor)
// 	}
// }

impl From<&'static str> for Block {
	fn from(s: &'static str) -> Self {
		deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
	}
}

impl Block {
	pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
		Block { block_header: header, transactions: transactions}
		//let (_, _, tree) = block.coded_merkle_roots(header.coded_merkle_roots_hashes.len(), header.rate);
		//Block { block_header: header, transactions: transactions, coded_merkle_tree: tree}
	}

	/// Returns block's merkle root.
	#[cfg(any(test, feature = "test-helpers"))]
	pub fn merkle_root(&self) -> H256 {
		let hashes = self.transactions.iter().map(Transaction::hash).collect::<Vec<H256>>();
		merkle_root(&hashes)
	}

	/// Returns block's witness merkle root.
	#[cfg(any(test, feature = "test-helpers"))]
	pub fn witness_merkle_root(&self) -> H256 {
		let hashes = match self.transactions.split_first() {
			None => vec![],
			Some((_, rest)) => {
				let mut hashes = vec![H256::from(0)];
				hashes.extend(rest.iter().map(Transaction::witness_hash));
				hashes
			},
		};
		merkle_root(&hashes)
	}

	//Returns hashes of the symbols on the top layer of coded Merkle tree 
	//#[cfg(any(test, feature = "test-helpers"))]
	pub fn coded_merkle_roots(&self, header_size: u32, rate: f32, codes: Vec<Code>) -> (usize, Vec<H256>, Vec<Symbols>) {
		let mut trans_byte = self.transactions.iter().map(Transaction::bytes).collect::<Vec<Bytes>>();
		let mut data: Vec<u8> = vec![];
		for j in 0..trans_byte.len(){
			data.append(&mut trans_byte[j].clone().into());
		}
		let original_size = data.len();
		if original_size% BASE_SYMBOL_SIZE > 0 {
			let padding = (original_size/BASE_SYMBOL_SIZE + 1) * BASE_SYMBOL_SIZE - original_size;
			for i in 0..padding {
				data.push(0x00);
			}
		} 
		let k = data.len()/BASE_SYMBOL_SIZE;
		let mut symbols: Vec<SymbolBase> = Vec::<SymbolBase>::with_capacity(k);
		for l in 0..k {
			let mut symbol: SymbolBase = [0x00; BASE_SYMBOL_SIZE];
			symbol.copy_from_slice(&data[l * BASE_SYMBOL_SIZE .. (l + 1) * BASE_SYMBOL_SIZE]);
			symbols.push(symbol);
		}
		let (roots, tree) = coded_merkle_roots(&symbols, header_size, rate, codes);
		(original_size, roots, tree)
	}

	//Returns a Merkle proof for some symbol index at some level of the coded merkle tree
    //A proof for a particular symbol is a list of symbols in the upper levels
	//#[cfg(any(test, feature = "test-helpers"))]
	pub fn merkle_proof(&self, lvl: usize, index: u32, codes: Vec<Code>) -> Vec<SymbolUp> {
		//Construct the coded Merkle tree
		let header_size = self.block_header.coded_merkle_roots_hashes.len();
		let (_, _, tree) = self.coded_merkle_roots((header_size as u32), RATE, codes);

		let mut proof = Vec::<SymbolUp>::new();
		let mut moving_index = index;
		let mut moving_k = 0;
		let reduce_factor = ((AGGREGATE as f32) * RATE) as u32;
		match &tree[lvl] {
			Symbols::Base(syms) => {
				moving_k = ((syms.len() as f32) * RATE) as u32;
			}
			Symbols::Upper(syms) => {
				moving_k = ((syms.len() as f32) * RATE) as u32;
			}
		}
		for i in lvl..(tree.len() - 1) {
			moving_index = next_index(moving_index, moving_k, reduce_factor);
            if let Symbols::Upper(syms) = &tree[i + 1] {
                proof.push(syms[(moving_index as usize)]);
            }
            moving_k = moving_k / reduce_factor;
		}
		proof
	}

	pub fn transactions(&self) -> &[Transaction] {
		&self.transactions
	}

	pub fn header(&self) -> &BlockHeader {
		&self.block_header
	}

	#[cfg(any(test, feature = "test-helpers"))]
	pub fn hash(&self) -> H256 {
		self.block_header.hash()
	}
}

// #[cfg(test)]
// mod tests {
// 	use hash::H256;
// 	use super::*;
// 	use coded_merkle_roots::compute_hash;
// 	use constants::AGGREGATE;
// 	use std::cmp::Ordering;

// 	// Block 80000
// 	// https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
// 	// https://blockchain.info/rawblock/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6?format=hex
// 	#[test]
// 	fn test_block_merkle_root_and_hash() {
// 		let block: Block = "01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704e6ed5b1b014effffffff0100f2052a01000000434104b68a50eaa0287eff855189f949c1c6e5f58b37c88231373d8a59809cbae83059cc6469d65c665ccfd1cfeb75c6e8e19413bba7fbff9bc762419a76d87b16086eac000000000100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();
// 		let merkle_root = H256::from_reversed_str("8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719");
// 		let hash = H256::from_reversed_str("000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6");
// 		assert_eq!(block.merkle_root(), merkle_root);
// 		assert_eq!(block.hash(), hash);
// 	}

//     #[test]
// 	fn test_block_coded_merkle_roots() {
// 		let block: Block = "01000000ba8b9cda965dd8e536670f9ddec10e53aab14b20bacad27b9137190000000000190760b278fe7b8565fda3b968b918d5fd997f993b23674c0af3b6fde300b38f33a5914ce6ed5b1b01e32f570201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704e6ed5b1b014effffffff0100f2052a01000000434104b68a50eaa0287eff855189f949c1c6e5f58b37c88231373d8a59809cbae83059cc6469d65c665ccfd1cfeb75c6e8e19413bba7fbff9bc762419a76d87b16086eac000000000100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();
// 		let (original_size, roots, tree) = block.coded_merkle_roots(4, 0.5); 
// 		println!("The transactions of this block has {} bytes.",original_size);
// 		println!("The coded Merkle tree has {} level.",tree.len());

// 		let data_size = (((original_size as f32)/(BASE_SYMBOL_SIZE as f32)).ceil()) as u32;
// 		let step = (0.5 * (AGGREGATE as f32)) as u32;
// 		let n = (compute_hash(&tree[1]).len() as u32) * step;
// 		assert_eq!(compute_hash(&tree[tree.len() - 1]), roots); 
// 		assert_eq!((roots.len() as u32) * u32::pow(step, (tree.len() as u32) - 1), 
// 		(compute_hash(&tree[1]).len() as u32) * step); 
// 		assert!((data_size * 2) <= n);
//         assert!((data_size * 2) >= (n/step));
// 	}
// }
