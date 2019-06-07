use crypto::dhash256;
use hash::{H256, H512};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

//size of a symbol on the base layer in bytes
pub const BASE_SYMBOL_SIZE: u32 = 256;

//number if hashes to aggregate to form a new symbol on the upper layers of CMT
pub const AGGREGATE: u32 = 8;

//define the data type for a symbol on the base layer
pub struct SymbolBase([u8;BASE_SYMBOL_SIZE]);

//define the data type for a symbol on the upper layers
pub struct SymbolUp([H256;AGGREGATE]);

//a new type for a sequence of data symbols
pub enum  Symbols{
	Base(Vec<SymbolBase>),
	Upper(Vec<SymbolUp>),
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
		data.push(Symbol([0x00;BASE_SYMBOL_SIZE]));        
	}
	data
}

pub fn encoding(data: &Symbols, rate: f32) -> Symbols{
	match data {
		Symbols::Base(message) => {
			let mut coded: Vec<SymbolBase> = Vec::with_capacity((message.len() / rate) as u32);
			Symbols::Base(coded)
		},
		Symbols::Upper(message) => {
			let mut coded: Vec<SymbolUp> = Vec::with_capacity((message.len() / rate) as u32);
			Symbols::Upper(coded)
		},
	}
}

fn hashAggregate(coded: &Symbols, rate: f32) -> Symbols{
    struct SymbolSys([H256;(AGGREGATE * rate) as u32]);
    struct SymbolPar([H256;(AGGREGATE * (1-rate)) as u32]);

	let mut hashes = Vec<H256>::new();
	match coded {
		Symbols::Base(message) => {
			for i in 0..message.len() {
				hashes.push(dhash256(message[i]));
			}
		},
		Symbols::Upper(message) => {
			for i in 0..message.len() {
				hashes.push(dhash256(message[i]));
			}
		},
	}
    // n is numbe of coded symbols/hashes
	let n = hashes.len();
	// k is the number of new symbols after aggregation 
	let k = (n/AGGREGATE) as u32;

	let mut systematic = Vec::with_capacity(k);

	for i in 0..k {
		let mut partial = SymbolSys([H256;(AGGREGATE * rate) as u32])
	}

	let mut parity = Vec::with_capacity(k);
}



#[inline]
fn concat<T>(a: T, b: T) -> H512 where T: AsRef<H256> {
	let mut result = H512::default();
	result[0..32].copy_from_slice(&**a.as_ref());
	result[32..64].copy_from_slice(&**b.as_ref());
	result
}

/// Calculates the root of the merkle tree
/// https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees
pub fn coded_merkle_roots(symbols: &[SymbolBase], headerSize: u32, rate: f32) -> Vec<H256> {
    let data = pad(symbols, rate);
    let n = (data.len() / rate) as u32;
    let level = ((((n/headerSize) as f32).log2()/((rate * AGGREGATE) as f32).log2()) as u32) + 1;

    //Coded merkle tree is a vector of symbols on each layer
    let mut tree: Vec<Symbols> = Vec::with_capacity(level); 
    // Constructing the base layer
    let coded_data = encoding(&data, rate);
   
    tree.push(coded_data);

    for i in 0..(level-1) {
    	let new_data: Symbols = hashAggregate(&tree[i]);
    	tree.push(encoding(&new_data, rate));
    }



	if hashes.len() == 1 {
		return hashes[0].as_ref().clone();
	}
	let mut row = Vec::with_capacity(hashes.len() / 2);
	let mut i = 0;
	while i + 1 < hashes.len() {
		row.push((&hashes[i], &hashes[i + 1]));
		i += 2
	}

	// duplicate the last element if len is not even
	if hashes.len() % 2 == 1 {
		let last = &hashes[hashes.len() - 1];
		row.push((last, last));
	}
	let res: Vec<_>;
	// Only compute in parallel if there is enough work to benefit it
	if row.len() > 250 {
		res = row.par_iter().map(|x| merkle_node_hash(&x.0, &x.1)).collect();
	} else {
		res = row.iter().map(|x| merkle_node_hash(&x.0, &x.1)).collect();
	}
	merkle_root(&res)
}


/// Calculate merkle tree node hash
pub fn merkle_node_hash<T>(left: T, right: T) -> H256 where T: AsRef<H256> {
	dhash256(&*concat(left, right))
}

#[cfg(test)]
mod tests {
	use hash::H256;
	use super::merkle_root;

	// block 80_000
	// https://blockchain.info/block/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
	#[test]
	fn test_merkle_root_with_2_hashes() {
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
	fn test_merkle_root_with_5_hashes() {
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
