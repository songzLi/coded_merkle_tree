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
use decoder::{Code, Symbol};
use rand::distributions::{Distribution, Bernoulli, Uniform};
use CodingErr;

//#[derive(Debug, PartialEq, Clone, Serializable, Deserializable)]
#[derive(Clone)]
pub struct Block {
	pub block_header: BlockHeader,
	pub transactions: Vec<Transaction>,
	pub coded_tree: Vec<Symbols>, //Coded Merkle tree constructed from the transactions in the block
	pub block_size_in_bytes: usize, // size of transactions in the block, used to specify block size for tests
}

// index of the parent symbol on the coded Merkle tree
// k is number of systematic symbols in the current layer
pub fn next_index(index: u32, k: u32, reduce_factor: u32) -> u32 {
	if index <= k - 1 {
		index / reduce_factor
	}
	else {
		(index - k) / ((AGGREGATE as u32) - reduce_factor)
	}
}

// randomly sample a parity sibling of a systematic symbols
// a parity sibling refers to a parity symbol that shares the same parent symbol as the systematic symbol
pub fn sample_parity_sibling(index: u32, n: u32, header_size: u32, reduce_factor: u32) -> u32 {
    // Use the same symbol if v is true, otherwise use a random sibling sampled uniformly
	let d = Bernoulli::new(RATE as f64).unwrap();
    let v = d.sample(&mut rand::thread_rng());
    if v == true {return index;}
    else {
    	let k = ((n as f32) * RATE) as u32;
        let mut siblings: Vec<u32> =  vec![];
			if n > header_size { //if this is not the last layer
				let parent: u32 = next_index(index, k, reduce_factor);
			    for i in k..n {
				    if next_index(i as u32, k, reduce_factor) == parent {
					    siblings.push(i as u32);
				    }
			    }
			} else {
			    for i in k..n {
				    siblings.push(i as u32);
			    }
		    }
    	let l = siblings.len();
        let die = Uniform::from(0..l); //uniformly pick one sibling symbol to sample
        let throw = die.sample(&mut rand::thread_rng());
        return siblings[throw];
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

// impl From<&'static str> for Block {
// 	fn from(s: &'static str) -> Self {
// 		deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
// 	}
// }

impl Block {
	// construct a block 
	// correct indicates if we will perform coding correctly or not on each level of the CMT
	pub fn new(header: BlockHeader, transactions: &Vec<Transaction>, block_size: usize, header_size: u32, 
		codes: &Vec<Code>, correct: Vec<bool>) -> Self {
		// let block = Block {block_header: header.clone(), transactions: transactions.clone(), 
		// coded_tree: vec![], block_size_in_bytes: block_size};

		let block = Block {block_header: header.clone(), transactions: transactions.to_vec(), 
			coded_tree: vec![], block_size_in_bytes: block_size};
		//Compute coded Merkle tree and hashes of the last layer from the transactions	
		let (_, root_hashes, tree) = block.coded_merkle_roots(header_size, RATE, codes.to_vec(), correct);
		let mut new_header = header;
		// Merkle root from transactions
		// base unit is transaction
		new_header.merkle_root_hash = block.merkle_root();
		// Root hashes of CMT from transactions
		// base unit is symbol
		new_header.coded_merkle_roots_hashes = root_hashes;
		Block { block_header: new_header, transactions: transactions.to_vec(), coded_tree: tree, block_size_in_bytes: block_size}
	}

	/// Returns block's merkle root.
	//#[cfg(any(test, feature = "test-helpers"))]
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
	pub fn coded_merkle_roots(&self, header_size: u32, rate: f32, codes: Vec<Code>, correct: Vec<bool>) -> (usize, Vec<H256>, Vec<Symbols>) {
		//Convert transactions into bytes and concatenate them into a Vec<u8>
		let mut trans_byte = self.transactions.iter().map(Transaction::bytes).collect::<Vec<Bytes>>();
		let mut data: Vec<u8> = vec![];
		for j in 0..trans_byte.len(){
			data.append(&mut trans_byte[j].clone().into());
		}

		let transactions_size_in_bytes = data.len();

		//Append random data to meet target BLOCK_SIZE
		if transactions_size_in_bytes < self.block_size_in_bytes {
			for _ in 0..(self.block_size_in_bytes - transactions_size_in_bytes) {
				let die = Uniform::from(0u8..=255u8);
				let new_byte = die.sample(&mut rand::thread_rng());
				data.push(new_byte);
			}
		}
		//generate fake transaction data of size self.block_size_in_bytes bytes
		// let mut data: Vec<u8> = vec![];
		// for j in 0..self.block_size_in_bytes {
		// 	let die = Uniform::from(0u8..=255u8);
   //           let new_byte = die.sample(&mut rand::thread_rng());
		// 	data.push(new_byte);
		// }

        // pad zeros to make the base layer integer number of base symbols
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
		// construct CMT and the root hashes
		let (roots, tree) = coded_merkle_roots(&symbols, header_size, rate, codes, correct);
		(original_size, roots, tree)
	}

	//Returns a Merkle proof for some symbol index at some level of the coded merkle tree
    //A proof for a particular symbol is a list of symbols in the upper levels
	//#[cfg(any(test, feature = "test-helpers"))]
	pub fn merkle_proof(&self, lvl: usize, index: u32) -> (Vec<SymbolUp>, Vec<u32>) {
		//Construct the coded Merkle tree
		//let header_size = self.block_header.coded_merkle_roots_hashes.len();
		//let (_, _, tree) = self.coded_merkle_roots((header_size as u32), RATE, codes);
        
        // A proof is a vector of symbols on the upper layers of CMT, one from each layer
		let mut proof = Vec::<SymbolUp>::new();
		let mut proof_indices: Vec<u32> = vec![];
		let mut moving_index = index;
		let mut moving_k = 0;
		let reduce_factor = ((AGGREGATE as f32) * RATE) as u32;
		//match &tree[lvl] {
		match &self.coded_tree[lvl] {
			Symbols::Base(syms) => {
				moving_k = ((syms.len() as f32) * RATE) as u32;
			}
			Symbols::Upper(syms) => {
				moving_k = ((syms.len() as f32) * RATE) as u32;
			}
		}
		// find the index of next symbol in the proof on the next layer of CMT
		for i in lvl..(self.coded_tree.len() - 1) {
			moving_index = next_index(moving_index, moving_k, reduce_factor);
			proof_indices.push(moving_index.clone()); // add the index of a symbol in the proof
            if let Symbols::Upper(syms) = &self.coded_tree[i + 1] {
                proof.push(syms[(moving_index as usize)]); //add a new symbol to proof
            }
            moving_k = moving_k / reduce_factor;
		}
		(proof, proof_indices)
	}
    
    //take s random symbols from the base layer, and their Merkle proofs as symbols from other layers
	pub fn sampling_to_decode(&self, s: u32) -> (Vec<Vec<Symbol>>, Vec<Vec<u64>>) {
		let mut symbols_all_levels: Vec<Vec<Symbol>> = vec![];
		let mut indices_all_levels: Vec<Vec<u64>> = vec![];
		let reduce_factor = ((AGGREGATE as f32) * RATE) as u32;
		let header_size = self.block_header.coded_merkle_roots_hashes.len();

		if let Symbols::Base(syms) = &self.coded_tree[0] { // get the symbols on the base layer, syms is a vector of base symbols
			let n = syms.len();

            //Create random seed
			let mut rng = rand::thread_rng();
			//Create a random variable uniform between 0 to n-1
			let die = Uniform::from(0..n);

			let throw = die.sample(&mut rng); //sample a symbol index on the base layer
			let (up_symbols, up_indices) = self.merkle_proof(0, throw as u32); //obtain symbols on the upper layers and their indices
			symbols_all_levels.push(vec![Symbol::Base(syms[throw].clone())]);
			indices_all_levels.push(vec![throw.clone() as u64]);
             
            // Each sample in the proof is a symbol for its own layer 
            // To uniformly sample upper layer, we randomly choose the sampled symbol on the upper layer
            // as either the proof itself or one of its parity sibling (chosen uniformly at random)
			for j in 0..up_symbols.len() { 
				if let Symbols::Upper(syms_up) = &self.coded_tree[j+1] {
					let chosen_index = sample_parity_sibling(up_indices[j], syms_up.len() as u32, header_size as u32, reduce_factor);
					let chosen_symbol = syms_up[chosen_index as usize]; //this symbols has type [H256; AGGREGATE]
					//convert chosen_symbol to type "Symbol" 
					let mut sym_byte = [0u8; 32 * AGGREGATE];
					for t in 0..AGGREGATE {
						let temp: [u8; 32] = chosen_symbol[t].clone().into();
        		        sym_byte[t * 32 .. (t+1) * 32].copy_from_slice(&temp);
        		    }
        		    // push to symbols and indices
					symbols_all_levels.push(vec![Symbol::Upper(sym_byte)]);
			        indices_all_levels.push(vec![chosen_index as u64]);
				}
			}

			for i in 1..s { //sample s times with replacement uniformly at random
			    let die = Uniform::from(0..n);
				let throw = die.sample(&mut rand::thread_rng()); //sample a base index
				let (up_symbols, up_indices) = self.merkle_proof(0, throw as u32);

				//push to base level if not seen before
				if !indices_all_levels[0].contains(&(throw as u64)) {
					symbols_all_levels[0].push(Symbol::Base(syms[throw].clone()));
			        indices_all_levels[0].push(throw.clone() as u64);
				}

				//push to upper levels if not seen before
				for j in 0..up_symbols.len() {
					if let Symbols::Upper(syms_up) = &self.coded_tree[j+1] {
						let chosen_index = sample_parity_sibling(up_indices[j], syms_up.len() as u32, header_size as u32, reduce_factor);
						if !indices_all_levels[j+1].contains(&(chosen_index as u64)) {
							let chosen_symbol = syms_up[chosen_index as usize]; //this symbols has type [H256; AGGREGATE]
					        //convert chosen_symbol to type Symbol 
					        let mut sym_byte = [0u8; 32 * AGGREGATE];
			                for t in 0..AGGREGATE {
				                let temp: [u8; 32] = chosen_symbol[t].clone().into();
		                        sym_byte[t * 32 .. (t+1) * 32].copy_from_slice(&temp);
		                    }
		                    // push to symbols and indices
			                symbols_all_levels[j+1].push(Symbol::Upper(sym_byte));
	                        indices_all_levels[j+1].push(chosen_index as u64);
	                    }
			        }
			    }
			}
		}
		(symbols_all_levels, indices_all_levels)
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
