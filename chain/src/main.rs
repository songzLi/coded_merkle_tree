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
use chain::constants::{BLOCK_SIZE, BASE_SYMBOL_SIZE, AGGREGATE, RATE, HEADER_SIZE, NUMBER_ITERATION};
use chain::coded_merkle_roots::{Symbols, SymbolBase, SymbolUp, coded_merkle_roots};
use chain::merkle_root::merkle_root;
use chain::decoder::{Code, Symbol, Decoder, TreeDecoder, CodingErr, IncorrectCodingProof};

// obtain a code represented by symbols from the form represented by parities
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

	//Read encoding matrix
	let filename = String::from("chain/src/LDPC_codes/k=") + &k.to_string() + &String::from("_encode.txt");
    // Open the file in read-only mode (ignoring errors).
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);
    
    //parity equations for encoding
    let mut parities_encoding: Vec<Vec<u64>> = vec![];
    for (index, line) in reader.lines().enumerate() {
        let line = line.unwrap(); // Ignore errors.
        let parity: Vec<u64> = line.split_whitespace().map(|s| s.parse().unwrap()).collect();
        parities_encoding.push(parity);
    }

    //Read decodeing matrix
    let filename = String::from("chain/src/LDPC_codes/k=") + &k.to_string() + &String::from("_decode.txt");
    // Open the file in read-only mode (ignoring errors).
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);
    
    //parity equations for decoding
    let mut parities_decoding: Vec<Vec<u64>> = vec![];
    for (index, line) in reader.lines().enumerate() {
        let line = line.unwrap(); // Ignore errors.
        let parity: Vec<u64> = line.split_whitespace().map(|s| s.parse().unwrap()).collect();
        parities_decoding.push(parity);
    }

    // Read the file line by line. Each line represent a parity equation.
    // for (index, line) in reader.lines().enumerate() {
    //     let line = line.unwrap(); // Ignore errors.
    //     let parity: Vec<u64> = line.split_whitespace().map(|s| s.parse().unwrap()).collect();
    //     if index < ((n - k) as usize) {
    //     	parities_encoding.push(parity.clone());
    //     	parities_decoding.push(parity);
    //     }
    //     else {//extra parity equations to help decoding
    //     	parities_decoding.push(parity); 
    //     }
    // }
     
    //Generate one code for encoding, and one code for decoding
    (Code {parities: parities_encoding.clone(), symbols: convert_parity_to_symbol(parities_encoding, n)}, 
    	Code {parities: parities_decoding.clone(), symbols: convert_parity_to_symbol(parities_decoding, n)})
}

//Read all codes for all coded Merkle tree layers
fn read_codes(k_set: Vec<u64>) -> (Vec<Code>, Vec<Code>) {
	let mut codes_for_encoding: Vec<Code> = vec![];
	let mut codes_for_decoding: Vec<Code> = vec![];
	for i in k_set.iter() {
		let (code_e, code_d) = read_code_from_file(*i);
		codes_for_encoding.push(code_e);
		codes_for_decoding.push(code_d);
	}
	(codes_for_encoding, codes_for_decoding)
}

fn test(block: &Block, num_samples: &Vec<u32>, codes_for_decoding: &Vec<Code>) -> Vec<Result<(), IncorrectCodingProof>> {
	let mut decoding_results = vec![];
	//Try different sample sizes to decode
	for s in num_samples.iter() {
		//initiate the decoder for coded Merkle tree
		let mut decoder: TreeDecoder = TreeDecoder::new(codes_for_decoding.to_vec(), &block.block_header.coded_merkle_roots_hashes);
        //take s symbols with replacement unifromly at random from the base layer of CMT
		let (symbols_all_levels, indices_all_levels) = block.sampling_to_decode(*s);
		decoding_results.push(decoder.run_tree_decoder(symbols_all_levels, indices_all_levels));
	}
	decoding_results
}

fn main() {
	//Here we test our coded Merkle tree (CMT) codes using parmeters from reference designs
	//A reference design specifies:

	//1. Blocksize(size of transactions), and symbol size on the base layer, hence we know # of systematic symbols k.
	//2. Number of hashes to aggregate on higher layer of CMT
	//3. Number of hashes in the block header.
	//4. All codes on all levels of CMT

	//For each reference, we have the following two tests:
	//1. Stopping set test: randomly sample a subset of symbols on each layer of CMT, and see if we can decode the entire tree
	//2. Incorrect-coding test: flip the bits of parity symbols after encoding, and use flipped symbols to construct CMT.
    //Check if the decoder correctly generates the incorrect-coding proof.

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

	let header_1 = header.clone(); //header for first test
	let header_2 = header; //header for second test

    // Create transactions
	let t = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000";
	let transaction_size = String::from(t).len();
	let num_transactions = BLOCK_SIZE / (transaction_size as u64);

	let transactions: Vec<Transaction> = vec![t.into();num_transactions as usize];
    
    // number of systematic symbols for the codes on the four layers of CMT
    let k_set: Vec<u64> = vec![512, 256, 128, 64];
    let (codes_for_encoding, codes_for_decoding) = read_codes(k_set);

    //Start tests

    //Test 1: Nornal mode, no coding error
    //block encoding
    let block: Block = Block::new(header_1, &transactions, BLOCK_SIZE as usize, HEADER_SIZE, &codes_for_encoding, vec![true; codes_for_encoding.len()]);
    
    //block decoding
    let num_samples = vec![1500, 1600, 1700, 1800, 1900, 2000];
    let mut successful_decoding_probability: Vec<f32> = vec![0.0;num_samples.len()];
    for i in 0..NUMBER_ITERATION { //try over NUMBER_ITERATION times, each time randomly takes num_samples symbols
    	let decoding_results: Vec<Result<(), IncorrectCodingProof>> = test(&block, &num_samples, &codes_for_decoding); 
    	for j in 0..num_samples.len() {
    		match &decoding_results[j] {
    			Ok(()) => {
    				successful_decoding_probability[j] += 1.0/(NUMBER_ITERATION as f32);
    			},
    			Err(proof) => {},
    		}
    	}
    }
    for j in 0..num_samples.len() {
    	println!("The probability of successful decoding with {} randomly sampled symbols is {}.", num_samples[j], successful_decoding_probability[j]);
    } 
    

    
    //Test 2: With incorrect coding

    //specify error pattern
    let mut error_pattern = vec![true; codes_for_encoding.len()];
    error_pattern[0] = false;
    //error_pattern[1] = false;
    
    //block encoding with the bits of first parity symbol flipped 
	let block: Block = Block::new(header_2, &transactions, BLOCK_SIZE as usize, HEADER_SIZE, &codes_for_encoding, error_pattern);
    
    //block decoding
	let num_samples = vec![2048];
	for i in 0..10 { //run for 10 times, each time the error should be caught
        let decoding_results: Vec<Result<(), IncorrectCodingProof>> = test(&block, &num_samples, &codes_for_decoding);
    } 
}










