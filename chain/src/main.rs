use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str;

extern crate rustc_hex as hex;
extern crate heapsize;
extern crate primitives;
extern crate rayon;
extern crate bitcrypto as crypto;
extern crate serialization as ser;
extern crate rand;
extern crate chain;

#[macro_use]
extern crate serialization_derive;

use primitives::{hash, bytes, bigint, compact};
use ser::{deserialize, serialize};
use bytes::Bytes;
use hash::H256;
use rand::distributions::{Distribution, Bernoulli, Uniform};

use chain::block_header::BlockHeader;
use chain::transaction::{Transaction, TransactionInput, TransactionOutput, OutPoint};
use chain::block::Block;
use chain::constants::{BLOCK_SIZE, BASE_SYMBOL_SIZE, AGGREGATE, RATE, HEADER_SIZE};
use chain::coded_merkle_roots::{Symbols, SymbolBase, SymbolUp, coded_merkle_roots};
use chain::merkle_root::merkle_root;
use chain::decoder::{Code, Symbol, Decoder, TreeDecoder, CodingErr};

fn convert_parity_to_symbol(parities: Vec<Vec<u64>>, n: u64) -> Vec<Vec<u64>> {
	let mut symbols: Vec<Vec<u64>> = vec![vec![];n as usize];
	for i in 0..parities.len(){
		let parity = &parities[i];
		for s in parity.iter() {
			symbols[*s as usize].push(i as u64);
		}
	}
	symbols
}

fn read_code_from_file(k: u64) -> (Code, Code) {
    //compute number of coded symbols
	let n = ((k as f32) / RATE ) as u64;
	let filename = String::from("src/code") + &k.to_string() + &String::from(".txt");
    // Open the file in read-only mode (ignoring errors).
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);
    
    //parity equations for encoding
    let mut parities_encoding: Vec<Vec<u64>> = vec![];
    //parity equations for decoding
    let mut parities_decoding: Vec<Vec<u64>> = vec![];

    //symbol equations for encoding
    // let symbols_encoding: Vec<Vec<u64>> = vec![];
    // //symbol equations for decoding
    // let symbols_decoding: Vec<Vec<u64>> = vec![];

    // Read the file line by line. Each line represent a parity equation.
    for (index, line) in reader.lines().enumerate() {
        let line = line.unwrap(); // Ignore errors.
        let parity: Vec<u64> = line.split_whitespace().map(|s| s.parse().unwrap()).collect();
        if index < ((n - k) as usize) {
        	parities_encoding.push(parity.clone());
        	parities_decoding.push(parity);
        }
        else {//extra parity equations to help decoding
        	parities_decoding.push(parity); 
        }
    }
     
    //Generate one code for encoding, and one code for decoding
    (Code {parities: parities_encoding.clone(), symbols: convert_parity_to_symbol(parities_encoding, n)}, 
    	Code {parities: parities_decoding.clone(), symbols: convert_parity_to_symbol(parities_decoding, n)})
}

// fn test(block: Block, num_samples: Vec<u32>, codes: Vec<Code>){
// 	//Try different sample sizes to decode
// 	for s in num_samples.iter() {
// 		let mut decoder: TreeDecoder = TreeDecoder::new(codes, block.block_header.coded_merkle_roots_hashes);
//         //take s symbols with replacement unifromly at random from the base layer of CMT
// 		let (symbols_all_levels, indices_all_levels) = block.sampling_to_decode(*s);
// 		let decoding_result = decoder.run_tree_decoder(symbols_all_levels, indices_all_levels); 
// 		match decoding_result {
// 			Ok(()) => {

// 			},
// 			Err(proof) => {

// 			}
// 		}

// 	}
// }


fn main() {
	//Here we test our coded Merkle tree (CMT) codes using parmeters from reference designs
	//A reference design specifies:

	//1. Blocksize(size of transactions), and symbol size on the base layer, hence we know # of systematic symbols k.
	//2. Number of hashes to aggregate on higher layer of CMT
	//3. Number of hashes in the block header.
	//4. All codes on all levels of CMT

	//For each reference, we have the following two tests:
	//1. Stopping set test: randomly sample a subset of symbols on each layer of CMT, and see if we can decode the entire tree
	//2. Incorrect-coding test: replace coded symbols with random symbols, and check if the code correctly generates 
	//   the incorrect-coding proof

	//Initialize a block
	//Initialize the block header
	let header = BlockHeader {
			version: 1,
			previous_header_hash: H256::default(),
			merkle_root_hash: H256::default(),
			time: 4u32,
			bits: 5.into(),
			nonce: 6u32,
			coded_merkle_roots_hashes: vec![H256::default(); 8],
		};

    // Create transactions
	let t = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000";
	let transaction_size = String::from(t).len();
	let num_transactions = BLOCK_SIZE / (transaction_size as u64);

	let transactions: Vec<Transaction> 
	= vec!["0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();num_transactions as usize];
    


	//let block: Block = Block::new(header, transactions, BLOCK_SIZE, HEADER_SIZE, codes, vec![true; codes.len()]);
    
    //let mut error_pattern = vec![true; codes.len()];
    //error_pattern[0] = false;
	//let block: Block = Block::new(header, transactions, block_size, HEADER_SIZE, codes, vec![true; codes.len()]);

}










