use constants::{BASE_SYMBOL_SIZE, AGGREGATE, RATE};
use {Symbols, SymbolBase, SymbolUp};
use hash::H256;

pub enum Symbol {
	Base([u8; BASE_SYMBOL_SIZE]),
	Upper([u8; 32 * AGGREGATE]),
} 

pub struct Decoder {
	pub level: u64,
	pub n: u64,
	pub k: u64,
	pub p: u64,

	pub parities: Vec<Vec<u64>>,
	pub symbols: Vec<Vec<u64>>,

	pub symbol_values: Vec<Option<Symbol>>,
    pub parity_values: Vec<Symbol>,
    pub parity_degree: Vec<u32>,
    pub degree_1_parities: Vec<u64>, 
    pub degree_2_parities: Vec<u64>,

    pub num_decoded_sys_symbols: u64,
    pub num_decoded_symbols: u64,
}

impl Decoder {
	pub fn new (level: u64, parities: Vec<Vec<u64>>, symbols: Vec<Vec<u64>>) -> Self {
		let n: u64 = symbols.len() as u64;
		let p: u64 = parities.len() as u64;
		let k = n - p;


		let parity_val = match level {
			0 => vec![Symbol::Base([0u8; BASE_SYMBOL_SIZE]); p as usize],
			_ => vec![Symbol::Upper([0u8; 32 * AGGREGATE]); p as usize],
		};

		// if level == 0 {
		// 	let parity_val = vec![Symbol::Base([0u8; BASE_SYMBOL_SIZE]); p];
		// } else {
		// 	let parity_val = vec![Symbol::Upper([0u8; 32 * AGGREGATE]); p];
		// }

		Decoder {
			n: n, k: k, p: p,
			parities: parities, symbols: symbols,
			symbol_values: vec![None; n],
			parity_values: parity_val,
			degree_1_parities: vec![], degree_2_parities: vec![],
			num_decoded_sys_symbols: 0, num_decoded_symbols: 0,
		}
	}








}