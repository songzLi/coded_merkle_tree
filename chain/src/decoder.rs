use constants::{BASE_SYMBOL_SIZE, AGGREGATE, RATE, HEADER_SIZE};
use std::cmp;
use std::ops::BitXor;
use {Symbols, SymbolBase, SymbolUp};
use hash::H256;
use crypto::dhash256;
use CodingErr;

#[derive(Clone, Copy)]
pub enum Symbol {
	Base([u8; BASE_SYMBOL_SIZE]),
	Upper([u8; 32 * AGGREGATE]),
	Empty,
} 

pub struct IncorrectCodingProof {
	pub error_type: CodingErr,
	pub level: u32,
	pub symbols: Vec<Symbol>,
	pub indices: Vec<u64>,
	pub parity_index: u64,
	pub proofs: Vec<Vec<Symbol>>
}

#[derive(Clone)]
//A code is specified by its parity-check matrix, which is represented by parities and symbols vectors
pub struct Code {
	pub parities: Vec<Vec<u64>>,
	pub symbols: Vec<Vec<u64>>,
}


pub struct TreeDecoder {
	pub n: u64, //block length of code on the base layer of the tree
	pub height: u32,
	pub decoders: Vec<Decoder>,
	pub hashes: Vec<Vec<H256>> //hashes of all layers
}

#[derive(Clone)]
pub struct Decoder {
	pub level: u32,
	pub n: u64,
	pub k: u64,
	pub p: u64,

	pub code: Code, //code shall not change during decoding

	pub parities: Vec<Vec<u64>>,
	pub symbols: Vec<Vec<u64>>,

	pub symbol_values: Vec<Symbol>,
    pub parity_values: Vec<Symbol>,
    pub parity_degree: Vec<u32>,
    pub degree_1_parities: Vec<u64>, 

    pub num_decoded_sys_symbols: u64,
    pub num_decoded_symbols: u64,
}

//Convert decoded symbols of the current layer to the hashes of the previous layer
fn symbol_to_hash(symbols: &Vec<Symbol>) -> Vec<H256> {
    let reduce_factor = ((AGGREGATE as f32) * RATE) as u64;

	let number_of_hashes = symbols.len() * AGGREGATE; 
	let mut previous_hashes = vec![H256::default();number_of_hashes];

    //convert each symbol to a vector of hashes
	let mut symbols_in_hashes: Vec<SymbolUp> = vec![];
	for i in 0..symbols.len() {
		//convert symbols[i] to a vector of hashes
		let mut symbol_in_hash = [H256::default(); AGGREGATE];
		if let Symbol::Upper(symbol_in_bytes) = symbols[i] {
			for j in 0..AGGREGATE {
				let mut h = [0u8; 32];
				h.copy_from_slice(&symbol_in_bytes[j*32..(j*32+32)]);
			    symbol_in_hash[j] = H256::from(h);
		    }
		}
		symbols_in_hashes.push(symbol_in_hash);
	}
    
    //number of systematic symbols on the previous level
	let k = ((previous_hashes.len() as f32) * RATE) as u64;

	for index in 0..previous_hashes.len() {
		let mut hash_index = 0;

        // current symbol is a systematic symbol
		if (index as u64) <= k - 1 {
			hash_index = (index as u64) % reduce_factor;
		}
		// current symbol is a parity symbol
		else {
			hash_index = ((index as u64) - k) % ((AGGREGATE as u64) - reduce_factor) + reduce_factor;
		}

		previous_hashes[index] = symbols_in_hashes[next_index(index as u64, k, reduce_factor) as usize][hash_index as usize];
	}

	previous_hashes
}


//return if a symbol is equal to zero or not
fn symbol_equal_to_zero(symbol: Symbol) -> bool {
	let mut flag = true;
	match symbol {
		Symbol::Base(decoded) => {
			for j in 0..BASE_SYMBOL_SIZE {
				if decoded[j] != 0u8 {
					flag = false;
					break;
				}
			}	
		},
		Symbol::Upper(decoded) => {
			for j in 0..32 * AGGREGATE {
				if decoded[j] != 0u8 {
					flag = false;
					break;
				}
			}	
		},
		_ => {}
	}
	flag
}

fn next_index(index: u64, k: u64, reduce_factor: u64) -> u64 {
	if index <= k - 1 {
		index / reduce_factor
	}
	else {
		(index - k) / ((AGGREGATE as u64) - reduce_factor)
	}
}


fn remove_one_item(vector: &Vec<u64>, item: &u64) -> Vec<u64> {
	let mut new_vec = vec![]; 
	for i in 0..vector.len() {
		if vector[i] != *item {
			new_vec.push(vector[i].clone());
		}
	}
	new_vec
}


impl TreeDecoder {
	//Decode coded Merkle tree after receiving enough symbols on each level
	pub fn run_tree_decoder(&mut self, symbols_all_levels: Vec<Vec<Symbol>>, indices_all_levels: Vec<Vec<u64>>) 
	-> Result<Vec<Decoder>, IncorrectCodingProof> {
		let mut hash_proof = self.hashes[(self.height - 1) as usize].clone();

		for i in (0..self.height).rev() {
			let received_symbols = symbols_all_levels[i as usize].clone();
			let received_indices = indices_all_levels[i as usize].clone();
			let (mut new_symbols, mut new_symbol_indices, mut decoded) = self.decoders[i as usize].symbol_update_from_reception(
				received_symbols, received_indices);
			let mut progress = self.decoders[i as usize].parity_update(new_symbols, new_symbol_indices);
			//parity nodes are updated, now check if there is any incorrect coding
			for j in 0..self.decoders[i as usize].p {
				if self.decoders[i as usize].parity_degree[j as usize] == 0 { //all symbols associated to this parity are known
					if !symbol_equal_to_zero(self.decoders[i as usize].parity_values[j as usize]) {
						//construct incorrect coding proof
						let error_indices = self.decoders[i as usize].code.parities[j as usize].clone();
						let mut error_symbols: Vec<Symbol> = vec![];
						
						for t in error_indices.iter() {
							error_symbols.push(self.decoders[i as usize].symbol_values[*t as usize]);
						}
						return Err(self.generate_incorrect_coding_proof(CodingErr::NotZero, i, 
							j as u64, error_symbols, error_indices));
					} 
				}
			}

			if decoded {
				if i > 0 {
					//decoding done, use the systematic symbols as the hash proof for previous layer
				    self.hashes[(i-1) as usize] = symbol_to_hash(&self.decoders[i as usize].symbol_values[0..(self.decoders[i as usize].k as usize)].to_vec());
				    hash_proof = self.hashes[(i-1) as usize].clone();
				    continue;	
				} else {
					return Ok(self.decoders.clone());
				}							
			}

			// if progress {

			// }



			// //Peeling decoding
			// loop {
			// 	let progress = self.decoders[i].parity_update(new_symbols, new_symbol_indices);

			// }
			// //check for incorrect coding, parity by parity


		}
		return Ok(self.decoders.clone());

	}



	pub fn new(codes: Vec<Code>, header_hash: Vec<H256>) -> Self {
		let num_layers = codes.len();
		let base_length: u64 = codes[0].symbols.len() as u64;
		let mut decs: Vec<Decoder> = vec![];
		let mut hash_list: Vec<Vec<H256>> = vec![];
		for i in 0..num_layers {
			let code = &codes[i];
			let dec: Decoder = Decoder::new(i as u32, code.parities.to_vec(), code.symbols.to_vec());
			decs.push(dec);
			hash_list.push(vec![H256::default();code.symbols.len()]);
		}
		hash_list[num_layers-1] = header_hash;

		TreeDecoder {
			n: base_length,
			height: num_layers as u32,
			decoders: decs,
			hashes: hash_list,
		}
	}

	//Generate merkle proof for a symbol  
	pub fn generate_merkle_proof(&self, lvl: usize, index: u64) -> Vec<Symbol> {
		let header_size = self.hashes.len();

		let mut proof = Vec::<Symbol>::new();
		let mut moving_index = index;
		let mut moving_k = self.decoders[lvl].k;
		let reduce_factor = ((AGGREGATE as f32) * RATE) as u64;
		for i in lvl..((self.height - 1) as usize) {
			moving_index = next_index(moving_index, moving_k, reduce_factor);
            proof.push(self.decoders[i+1].symbol_values[moving_index as usize].clone());
            moving_k = moving_k / reduce_factor;
		}
		proof
	}

	pub fn generate_incorrect_coding_proof(&self, err_type: CodingErr, lvl: u32, parity: u64, symbols: Vec<Symbol>, indices: Vec<u64>)
	-> IncorrectCodingProof {
		let mut merkle_proofs: Vec<Vec<Symbol>> = vec![];
		for i in 0..indices.len() {
			merkle_proofs.push(self.generate_merkle_proof(lvl as usize, indices[i]));
		}
		IncorrectCodingProof {
			error_type: err_type,
	        level: lvl,
	        symbols: symbols,
	        indices: indices,
	        parity_index: parity,
	        proofs: merkle_proofs
	    }
	}
}


impl Decoder {
	pub fn new (level: u32, parities: Vec<Vec<u64>>, symbols: Vec<Vec<u64>>) -> Self {
		let n: u64 = symbols.len() as u64;
		let p: u64 = parities.len() as u64;
		let k = n - p;

		let mut parity_deg = vec![0u32; p as usize];
		for i in 0..(p as usize) {
			parity_deg[i] = parities[i].len() as u32; 
		}

		let mut parity_val = Vec::<Symbol>::new(); 
		let mut symbol_val = Vec::<Symbol>::new(); 

		match level {
			0 => {
				for _ in 0..p {
					parity_val.push(Symbol::Base([0u8; BASE_SYMBOL_SIZE]));
				}
			},
			_ => {
				for _ in 0..p {
					parity_val.push(Symbol::Upper([0u8; 32 * AGGREGATE]));
				}
			},
		}

		for _ in 0..n {
			symbol_val.push(Symbol::Empty);
		}

		Decoder {
			level: level, n: n, k: k, p: p,
			code: Code {parities: parities.clone(), symbols: symbols.clone()},
			parities: parities, symbols: symbols,
			symbol_values: symbol_val,
			parity_values: parity_val,
			parity_degree: parity_deg,
			degree_1_parities: vec![],
			num_decoded_sys_symbols: 0, num_decoded_symbols: 0,
		}
	}

	pub fn symbol_update_from_reception(&mut self, symbols: Vec<Symbol>, symbol_indices: Vec<u64>) -> (Vec<Symbol>,
		Vec<u64>, bool) {
		let mut out_symbols = Vec::<Symbol>::new();
        let mut out_indices = Vec::<u64>::new();

        let length = cmp::min(symbols.len(), symbol_indices.len());
        for i in 0..length {
        	if let Symbol::Empty = self.symbol_values[(symbol_indices[i] as usize)] {
        		self.symbol_values[(symbol_indices[i] as usize)] = symbols[i].clone();
        		self.num_decoded_symbols += 1;
        		if symbol_indices[i] < self.k {
        			self.num_decoded_sys_symbols += 1;
        		}
        	}
        	out_symbols.push(symbols[i].clone());
        	out_indices.push(symbol_indices[i].clone());
        }

        (out_symbols, out_indices, self.num_decoded_symbols == self.n)
	}

	pub fn parity_update(&mut self, symbols: Vec<Symbol>, symbol_indices: Vec<u64>) -> bool {
		if  symbols.len() == 0 {
			return self.degree_1_parities.len() != 0;
		}
		let length = cmp::min(symbols.len(), symbol_indices.len());
		for i in 0..length {
			let (s, idx) = (symbols[i].clone(), symbol_indices[i].clone());
			let parity_list = self.symbols[idx as usize].clone(); // subset of parity nodes that will be affected by symbol s
			for parity in parity_list.iter() {
				//Update the value of each parity node symbol s connects to
				match (self.parity_values[*parity as usize], s) {
					(Symbol::Base(x), Symbol::Base(y)) => {
						let mut sum: [u8; BASE_SYMBOL_SIZE] = x.clone();
						for j in 0..BASE_SYMBOL_SIZE {
							sum[j] = sum[j].bitxor(y[j]);
						} 
						self.parity_values[*parity as usize] = Symbol::Base(sum);
					},
					(Symbol::Upper(x), Symbol::Upper(y)) => {
						let mut sum: [u8; 32 * AGGREGATE] = x.clone();
						for j in 0..(32 * AGGREGATE) {
							sum[j] = sum[j].bitxor(y[j]);
						} 
						self.parity_values[*parity as usize] = Symbol::Upper(sum);
					},
					(_, _) => (),
				}
				self.parity_degree[*parity as usize] -= 1;
				if self.parity_degree[*parity as usize] == 1 {
                    self.degree_1_parities.push(parity.clone());
				}
				self.parities[*parity as usize] = remove_one_item(&self.parities[*parity as usize], &idx);
				self.symbols[idx as usize] = remove_one_item(&self.symbols[idx as usize], &parity);
			}
		}
		self.degree_1_parities.len() != 0
	}


	// pub fn symbol_update_from_degree_1_parities(&mut self) -> (Vec<Symbol>, Vec<u64>, bool) {
	// 	let mut symbols = Vec::<Symbol>::new();
 //        let mut symbol_indices = Vec::<u64>::new();

 //        for i in 0..self.degree_1_parities.len() {
 //        	let parity = self.degree_1_parities[i].clone();
 //        	if self.parities[parity as usize].len() > 0 {
 //        		let symbol_idx = self.parities[parity as usize][0];
 //        		if let Symbol::Empty = self.symbol_values[symbol_idx as usize] {
 //        			self.symbol_values[symbol_idx as usize] = self.parity_values[parity as usize];
 //        			self.num_decoded_symbols += 1; 
 //        			if symbol_idx < self.k {
 //                        self.num_decoded_sys_symbols += 1;
 //        			}
 //        			symbols.push(self.parity_values[parity as usize].clone());
 //                    symbol_indices.push(symbol_idx.clone());
 //        		} 
 //        	}
 //        }

 //        self.degree_1_parities = vec![];

 //        (symbols, symbol_indices, self.num_decoded_symbols == self.n)
	// }


	pub fn symbol_update_from_degree_1_parities(&mut self, hashes: Vec<H256>) 
	-> Result<(Vec<Symbol>, Vec<u64>, bool), (u32, u64, Vec<u64>, Vec<Symbol>)> {
		let mut symbols = Vec::<Symbol>::new();
        let mut symbol_indices = Vec::<u64>::new();

        for i in 0..self.degree_1_parities.len() {
        	let parity = self.degree_1_parities[i].clone();
        	if self.parities[parity as usize].len() > 0 {
        		let symbol_idx = self.parities[parity as usize][0];
        		if let Symbol::Empty = self.symbol_values[symbol_idx as usize] {
        			self.symbol_values[symbol_idx as usize] = self.parity_values[parity as usize]; //Symbol decoded

        			//now check if the decoded symbol matches its hash
        			let mut computed_hash = H256::default();
        			match self.symbol_values[symbol_idx as usize] {
        				Symbol::Base(decoded_sym) => {computed_hash = dhash256(&decoded_sym);},
        				Symbol::Upper(decoded_sym) => {computed_hash = dhash256(&decoded_sym);},
        				_ => {}
        			}
        			if computed_hash == hashes[symbol_idx as usize] {
        				self.num_decoded_symbols += 1; 
        			    if symbol_idx < self.k {
                            self.num_decoded_sys_symbols += 1;
                        }
        			    symbols.push(self.parity_values[parity as usize].clone());
                        symbol_indices.push(symbol_idx.clone());
                    } else {//coding is done incorrectly, return an incorrect-coding 
                    	println!("Incorrect coding detected on layer {} for parity equation #{}.",self.level,parity);
                    	// Preparing info for constructing incorrect coding proof
                    	let index_set: Vec<u64> = self.code.parities[parity as usize].clone();
                    	let mut correct_index_set: Vec<u64> = remove_one_item(&index_set, &symbol_idx);
                    	let mut symbols_in_proof: Vec<Symbol> = vec![];
                    	for j in 0..correct_index_set.len() {
                    		symbols_in_proof.push(self.symbol_values[j]);
                    	}
                    	correct_index_set.push(symbol_idx);
                    	return Err((self.level, parity, correct_index_set, symbols_in_proof));
                    }
                } 
            }
        }

        self.degree_1_parities = vec![];

        Ok((symbols, symbol_indices, self.num_decoded_symbols == self.n))
    }


	// pub fn peeling_decode(&mut self) -> bool {
	// 	loop {
	// 		let (symbols, symbol_indices, decoded) = self.symbol_update_from_degree_1_parities();
	// 		if decoded { return decoded; }
	// 		if symbols.len() > 0 { // new symbols get decoded
	// 			let keep_peeling = self.parity_update(symbols, symbol_indices);
	// 			if keep_peeling {continue;}
	// 		}
	// 		return self.num_decoded_symbols == self.n;
	// 	}
	// }




}

#[cfg(test)]
mod tests {
	use rand::thread_rng;
    use rand::seq::SliceRandom;
	use super::*;

	//Test for decoder for a (2,4)-regular LDPC code with (n,k) = (8,4)
	#[test]
	fn test_peeling_decoder1() {
		// let mut vec: Vec<u64> = (0..16).collect();
  //       vec.shuffle(&mut thread_rng());

  //       let mut symbols: Vec<Vec<u64>> = vec![];
  //       for i in 0..8 {
  //       	symbols.push(vec![vec[2*i]/4, vec[2*i+1]/4]);
  //       }

		// let mut parities: Vec<Vec<u64>> = vec![];
		// for i in 0..4 {
		// 	let mut parity = vec![];
		// 	for j in 0..8 {
		// 		if symbols[j].contains(&i) {
		// 			parity.push(j as u64);
		// 		}
		// 	}
		// 	parities.push(parity);
		// }

		let symbols: Vec<Vec<u64>> = vec![
		vec![0, 1], vec![1, 2], vec![2, 3], vec![3, 0], vec![0, 3], vec![1, 2], vec![2, 1], vec![3, 0]
		]; 

		let parities: Vec<Vec<u64>> = vec![
		vec![0, 3, 4, 7], vec![0, 1, 6, 5], vec![1, 2, 5, 6], vec![2, 3, 4, 7]
		];  

		let mut decoder = Decoder::new(0, parities, symbols);
		println!("Decoder initialized.");

		// let mut symbol_arrive: Vec<u64> = (0..8).collect();
		// symbol_arrive.shuffle(&mut thread_rng());
		let symbol_arrive: Vec<u64> = vec![3, 5, 7, 0, 4, 2, 6, 1];
		let mut count = 0;
		println!("Checkpoint.");

		loop {
			let (symbols, symbol_indices, decoded) = decoder.symbol_update_from_reception(
				vec![Symbol::Base([0u8;BASE_SYMBOL_SIZE])], vec![symbol_arrive[count]]);
			if decoded {break;}
			if decoder.parity_update(symbols, symbol_indices) {
				if decoder.peeling_decode() {break;}
			}
			count += 1;
		}
		println!("Finish decoding using {} coded symbols.", count + 1);

		let mut flag = true;
		for i in 0..8 {			
			if let Symbol::Base(decoded) = decoder.symbol_values[i] {
				for j in 0..BASE_SYMBOL_SIZE {
					if decoded[j] != 0u8 {
						flag = false;
						break;
					}
				}				
			}
			if flag == false {break;}
		}
		assert_eq!(flag, true);
	}

	// #[test]
	// fn test_peeling_decoder2() {

	// }
}




