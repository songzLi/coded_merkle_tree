use crypto::dhash256;
use hash::H256;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

//size of a symbol on the base layer in bytes
pub const BASE_SYMBOL_SIZE: usize = 256;

//number if hashes to aggregate to form a new symbol on the upper layers of CMT
pub const AGGREGATE: usize = 8;

//define the data type for a symbol on the base layer
pub type SymbolBase = [u8; BASE_SYMBOL_SIZE];

//define the data type for a symbol on the upper layers
pub type SymbolUp = [H256; AGGREGATE];

//a new type for a sequence of data symbols
pub enum  Symbols{
	Base(Vec<SymbolBase>),
	Upper(Vec<SymbolUp>),
} 

fn computeHash(coded: &Symbols) -> Vec<H256> {
	let mut roots = Vec::<H256>::new(); 
	if let Symbols::Upper(layer) = coded {
        for i in 0..layer.len(){
        	roots.push(dhash256(&layer[i]));
        }
	} 
	roots
}

fn pad(symbols: &[SymbolBase], rate: f32) -> Vec<SymbolBase> {
	let mut data = symbols.to_vec();
	let med = data.len();
	let mut x = 1.0;
	while x * rate < med {
		x *= rate * AGGREGATE; 
	}
	let difference = (x * rate - med) as u64;
	for i in 0..difference {
		data.push([0x00;BASE_SYMBOL_SIZE]);        
	}
	data
}

pub fn encoding(data: &Symbols, rate: f32) -> Symbols{
	match data {
		Symbols::Base(message) => {
			let mut coded: Vec<SymbolBase> = Vec::with_capacity((message.len() / rate) as usize);
			Symbols::Base(coded)
		},
		Symbols::Upper(message) => {
			let mut coded: Vec<SymbolUp> = Vec::with_capacity((message.len() / rate) as usize);
			Symbols::Upper(coded)
		},
	}
}

fn hashAggregate(coded: &Symbols, rate: f32) -> Symbols{
    //struct SymbolSys([H256;(AGGREGATE * rate) as u32]);
    //struct SymbolPar([H256;(AGGREGATE * (1-rate)) as u32]);

	let mut hashes = Vec::<H256>::new();
	match coded {
		Symbols::Base(message) => {
			for i in 0..message.len() {
				hashes.push(dhash256(&message[i]));
			}
		},
		Symbols::Upper(message) => {
			for i in 0..message.len() {
				hashes.push(dhash256(&message[i]));
			}
		},
	}
    // n is numbe of coded symbols/hashes
	let n = hashes.len();
	// k is the number of new symbols after aggregation 
	let k = (n/AGGREGATE) as u32;

	let mut new_data = Vec::with_capacity(k);

	for i in 0..k {
		let mut new_symbol: SymbolUp = [H256::default();AGGREGATE];
		for j in 0..((AGGREGATE * rate) as u32){
			new_symbol[j] = hashes[((i * AGGREGATE * rate) as u32) + j].clone();
		}
		for k in 0..((AGGREGATE * (1 - rate)) as u32){
			new_symbol[((AGGREGATE * rate) as u32) + k] = hashes[((n * rate + i * AGGREGATE * (1 - rate)) as u32) + k].clone();
		}
		new_data.push(new_symbol);
	}
	Symbols::Upper(new_data)
}

/// Calculates the roots of the coded Merkle tree
pub fn coded_merkle_roots(symbols: &[SymbolBase], headerSize: u32, rate: f32) -> (Vec<Symbols>, Vec<H256>) {
    let data = pad(symbols, rate);
    let n = (data.len() / rate) as u32;
    let level = ((((n/headerSize) as f32).log2()/((rate * AGGREGATE) as f32).log2()) as u32) + 1;

    //Coded merkle tree is a vector of symbols on each layer
    let mut tree: Vec<Symbols> = Vec::with_capacity(level); 
    // Construct the base layer
    let coded_data = encoding(&data, rate);
    tree.push(coded_data);

    // Construct upper layers
    for i in 0..(level-1) {
    	let new_data: Symbols = hashAggregate(&tree[i]);
    	tree.push(encoding(&new_data, rate));
    }

    (tree, computeHash(&tree.last()))	
}


#[cfg(test)]
mod tests {
	use hash::H256;
	use super::merkle_root;

	// block 80_000
	// https://blockchain.info/block/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
	#[test]
	fn test_coded_merkle_roots_with_2_hashes() {
		let tx1 = H256::from_reversed_str("c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25");
		let tx2 = H256::from_reversed_str("5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2");
		let expected = H256::from_reversed_str("8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719");

		let result = merkle_root(&[&tx1, &tx2]);
		let result2 = merkle_root(&[tx1, tx2]);
		assert_eq!(result, expected);
		assert_eq!(result2, expected);
	}

	// Test with 5 hashes
	#[test]
	fn test_coded_merkle_roots_with_5_hashes() {
		let mut vec = Vec::new();
		vec.push(H256::from_reversed_str("1da63abbc8cc611334a753c4c31de14d19839c65b2b284202eaf3165861fb58d"));
		vec.push(H256::from_reversed_str("26c6a6f18d13d2f0787c1c0f3c5e23cf5bc8b3de685dd1923ae99f44c5341c0c"));
		vec.push(H256::from_reversed_str("513507fa209db823541caf7b9742bb9999b4a399cf604ba8da7037f3acced649"));
		vec.push(H256::from_reversed_str("6bf5d2e02b8432d825c5dff692d435b6c5f685d94efa6b3d8fb818f2ecdcfb66"));
		vec.push(H256::from_reversed_str("8a5ad423bc54fb7c76718371fd5a73b8c42bf27beaf2ad448761b13bcafb8895"));
		let result = merkle_root(&vec);

		let expected = H256::from_reversed_str("3a432cd416ea05b1be4ec1e72d7952d08670eaa5505b6794a186ddb253aa62e6");
		assert_eq!(result, expected);
	}
}
