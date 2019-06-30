use crypto::dhash256;
use hash::H256;
use constants::{BASE_SYMBOL_SIZE, AGGREGATE, RATE};
use ser::{Serializable, Deserializable, deserialize, serialize};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

//define the data type for a symbol on the base layer
//#[derive(Serializable)]
pub type SymbolBase = [u8; BASE_SYMBOL_SIZE];

//define the data type for a symbol on the upper layers
//#[derive(Serializable)]
pub type SymbolUp = [H256; AGGREGATE];

//a new type for a sequence of data symbols
pub enum Symbols{
	Base(Vec<SymbolBase>),
	Upper(Vec<SymbolUp>),
} 

pub fn compute_hash(coded: &Symbols) -> Vec<H256> {
	let mut roots = Vec::<H256>::new(); 
	if let Symbols::Upper(layer) = coded {
        for i in 0..layer.len(){
        	let mut sym = [0u8; 32 * AGGREGATE];
        	for j in 0..AGGREGATE {
        		let temp: [u8; 32] = layer[i][j].clone().into();
        		sym[j * 32 .. (j+1) * 32].copy_from_slice(&temp);
        	}
        	roots.push(dhash256(&sym));
        }
	} 
	roots
}

fn pad(symbols: &[SymbolBase], rate: f32) -> Vec<SymbolBase> {
	let mut data = symbols.to_vec();
	let med = data.len() as f32;
	let mut x = 1.0;
	while x * rate < med {
		x *= rate * (AGGREGATE as f32); 
	}
	let difference = (x * rate - med) as u64;
	for _i in 0..difference {
		data.push([0x00;BASE_SYMBOL_SIZE]);        
	}
	data
}

pub fn encoding(data: &Symbols, rate: f32) -> Symbols {
	match data {
		Symbols::Base(message) => {
			let k = message.len();
			let n = ((k as f32) / rate) as usize;
			let mut coded: Vec<SymbolBase> = message.clone();
			for _i in k..n {
				coded.push([0x00; BASE_SYMBOL_SIZE]);
			}
			//println!("{} symbols on this level.", coded.len());
			Symbols::Base(coded)
		},
		Symbols::Upper(message) => {
			let k = message.len();
			let n = ((k as f32) / rate) as usize;
			let mut coded: Vec<SymbolUp> = message.clone();
			for _i in k..n {
				coded.push([H256::default(); AGGREGATE]);
			}
			//println!("{} symbols on this level.", coded.len());
			Symbols::Upper(coded)
		},
	}
}

fn hash_aggregate(coded: &Symbols, rate: f32) -> Symbols{
	let mut hashes = Vec::<H256>::new();
	match coded {
		Symbols::Base(message) => {
			for i in 0..message.len() {
				hashes.push(dhash256(&message[i]));
			}
		},
		Symbols::Upper(_message) => {
			// for i in 0..message.len() {
			// 	hashes.push(dhash256(&message[i]));
			// }
			hashes = compute_hash(&coded);
		},
	}
    // n is numbe of coded symbols/hashes
	let n = hashes.len();
	// k is the number of new symbols after aggregation 
	let k = (n/AGGREGATE) as u32;

	let mut new_data = Vec::with_capacity(k as usize);

	for i in 0..k {
		let mut new_symbol: SymbolUp = [H256::default(); AGGREGATE];
		for j in 0..(((AGGREGATE as f32) * rate) as usize){
			let index  = ((((i * (AGGREGATE as u32)) as f32) * rate) as u32) + (j as u32);
			new_symbol[j] = hashes[index as usize].clone();
		}
		for k in 0..(((AGGREGATE as f32) * (1.0 - rate)) as usize){
			let index = (((n as f32) * rate + (i as f32) * (AGGREGATE as f32) * (1.0 - rate)) 
				as u32) + (k as u32);
			new_symbol[(((AGGREGATE as f32) * rate) as usize) + k] = hashes[index as usize].clone();
		}
		new_data.push(new_symbol);
	}
	Symbols::Upper(new_data)
}

// Calculates the roots of the coded Merkle tree
pub fn coded_merkle_roots(symbols: &[SymbolBase], header_size: u32, rate: f32) -> (Vec<H256>, Vec<Symbols>) {
    let data = pad(symbols, rate);
    let n = ((data.len() as f32) / rate) as u32;
    let level = ((((n/header_size) as f32).log2()/(rate * (AGGREGATE as f32)).log2()) as u32) + 1;

    //Coded merkle tree is a vector of symbols on each layer
    let mut tree: Vec<Symbols> = Vec::with_capacity(level as usize); 
    // Construct the base layer
    let coded_data = encoding(&Symbols::Base(data), rate);
    tree.push(coded_data);

    // Construct upper layers
    for i in 0..(level-1) {
    	let new_data: Symbols = hash_aggregate(&tree[i as usize], rate);
    	tree.push(encoding(&new_data, rate));
    }
    (compute_hash(&tree[tree.len()-1]), tree)
}

#[cfg(test)]
mod tests {
	use hash::H256;
	use super::*;

	//Test for construction of a coded Merkle tree
	#[test]
	fn test_coded_merkle_roots1() {
		let symbols = [[0x0f; BASE_SYMBOL_SIZE]; 200]; //The tree has 200 symbols on the base layer
		let roots = Vec::<H256>::new();
		let tree = Vec::<Symbols>::new();
		//Construct a coded merkle tree with 16 coded symbols on the top layer 
		//Coding rate is 0.25, and hence the tree has 7 layers  
		let (roots, tree) = coded_merkle_roots(&symbols, 16, 0.25);  

		assert_eq!(roots.len(), 16);
		assert_eq!(tree.len(), 7);
		assert_eq!(compute_hash(&tree[tree.len() - 1]), roots); 
	}

	//Test for construction of another coded Merkle tree
	#[test]
	fn test_coded_merkle_roots2() {
		let symbols = [[0x0f; BASE_SYMBOL_SIZE]; 1000]; //The tree has 1000 symbols on the base layer
		let roots = Vec::<H256>::new();
		let tree = Vec::<Symbols>::new();
		//Construct a coded merkle tree with 4 coded symbols on the top layer 
		//Coding rate is 0.5, and hence the tree has 6 layers  
		let (roots, tree) = coded_merkle_roots(&symbols, 4, 0.5);  

		assert_eq!(roots.len(), 4);
		assert_eq!(tree.len(), 6);
		assert_eq!(compute_hash(&tree[tree.len() - 1]), roots); 
	}
}
