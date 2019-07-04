use constants::{BASE_SYMBOL_SIZE, AGGREGATE, RATE};
use std::cmp;
use std::ops::BitXor;
use {Symbols, SymbolBase, SymbolUp};
use hash::H256;


#[derive(Clone, Copy)]
pub enum Symbol {
	Base([u8; BASE_SYMBOL_SIZE]),
	Upper([u8; 32 * AGGREGATE]),
	Empty,
} 

pub struct Decoder {
	pub level: u64,
	pub n: u64,
	pub k: u64,
	pub p: u64,

	pub parities: Vec<Vec<u64>>,
	pub symbols: Vec<Vec<u64>>,

	pub symbol_values: Vec<Symbol>,
    pub parity_values: Vec<Symbol>,
    pub parity_degree: Vec<u32>,
    pub degree_1_parities: Vec<u64>, 

    pub num_decoded_sys_symbols: u64,
    pub num_decoded_symbols: u64,
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


impl Decoder {
	pub fn new (level: u64, parities: Vec<Vec<u64>>, symbols: Vec<Vec<u64>>) -> Self {
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
							sum[j].bitxor(y[j]);
						} 
						self.parity_values[*parity as usize] = Symbol::Base(sum);
					},
					(Symbol::Upper(x), Symbol::Upper(y)) => {
						let mut sum: [u8; 32 * AGGREGATE] = x.clone();
						for j in 0..(32 * AGGREGATE) {
							sum[j].bitxor(y[j]);
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


	pub fn symbol_update_from_degree_1_parities(&mut self) -> (Vec<Symbol>, Vec<u64>, bool) {
		let mut symbols = Vec::<Symbol>::new();
        let mut symbol_indices = Vec::<u64>::new();

        for i in 0..self.degree_1_parities.len() {
        	let parity = self.degree_1_parities[i].clone();
        	if self.parities[parity as usize].len() > 0 {
        		let symbol_idx = self.parities[parity as usize][0];
        		if let Symbol::Empty = self.symbol_values[symbol_idx as usize] {
        			self.symbol_values[symbol_idx as usize] = self.parity_values[parity as usize];
        			self.num_decoded_symbols += 1; 
        			if symbol_idx < self.k {
                        self.num_decoded_sys_symbols += 1;
        			}
        			symbols.push(self.parity_values[parity as usize].clone());
                    symbol_indices.push(symbol_idx.clone());
        		} 
        	}
        }

        self.degree_1_parities = vec![];

        (symbols, symbol_indices, self.num_decoded_symbols == self.n)
	}


	pub fn peeling_decode(&mut self) -> bool {
		loop {
			let (symbols, symbol_indices, decoded) = self.symbol_update_from_degree_1_parities();
			if decoded { return decoded; }
			if symbols.len() > 0 { // new symbols get decoded
				let keep_peeling = self.parity_update(symbols, symbol_indices);
				if keep_peeling {continue;}
			}
			return self.num_decoded_symbols == self.n;
		}
	}
}

#[cfg(test)]
mod tests {
	use hash::H256;
	use super::*;

	//Test for construction of a coded Merkle tree
	#[test]
	fn test_peeling_decoder1() {

	}

	//Test for construction of another coded Merkle tree
	#[test]
	fn test_peeling_decoder2() {

	}
}




