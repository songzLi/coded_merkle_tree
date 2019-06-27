use std::fmt;
use hex::FromHex;
use ser::{deserialize, serialize};
use crypto::dhash256;
use compact::Compact;
use hash::H256;
use constants::BASE_SYMBOL_SIZE;
use coded_merkle_roots::AGGREGATE;
use {Symbols, SymbolBase, SymbolUp};
use block::next_index;
use CodingErr;

#[derive(PartialEq, Clone, Serializable, Deserializable)]
pub struct BlockHeader {
	pub version: u32,
	pub previous_header_hash: H256,
	pub merkle_root_hash: H256,
	pub time: u32,
	pub bits: Compact,
	pub nonce: u32,
	pub coded_merkle_roots_hashes: Vec<H256>,//hashes of the symbols on the top layer of coded Merkle tree
	pub rate: f32, //coding rate to construct coded Merkle tree
	pub block_size: u32, // number of systematic symbols in the block 
	//pub code: //parity check matrix of the sparse code
}

impl BlockHeader {
	// Compute hash of the block header.
	#[cfg(any(test, feature = "test-helpers"))]
	pub fn hash(&self) -> H256 {
		block_header_hash(self)
	}

	// Verify the Merkle proof of an upper symbol using the hashes in the block header
	//#[cfg(any(test, feature = "test-helpers"))]
	pub fn verify_up(&self, symbol: SymbolUp, lvl: u32, index: u32, proof: &Vec<SymbolUp>) -> bool {
		let reduce_factor = ((AGGREGATE as f32) * self.rate) as u32;
		let mut current_symbol = symbol;
		let mut current_index = index;
		let mut current_lvl = lvl;
		let mut current_k = self.block_size / u32::pow(reduce_factor, lvl);

		for s in proof.iter() {
			let mut hash_index = 0;
			// current symbol is a systematic symbol
			if current_index <= current_k - 1 {
				hash_index = current_index % reduce_factor;
			}
			// current symbol is a parity symbol
			else {
				hash_index = (current_index - current_k) % ((AGGREGATE as u32) -
                                                       reduce_factor) + reduce_factor;
			}

            //convert a symbol to a byte stream
			let mut sym = [0u8; 32 * AGGREGATE];
        	for j in 0..AGGREGATE {
        		let temp: [u8; 32] = current_symbol[j].clone().into();
        		sym[j * 32 .. (j+1) * 32].copy_from_slice(&temp);
        	}

			if dhash256(&sym) != s[(hash_index as usize)]{
			    println!("Failed at level {} with symbol index {}.", current_lvl, current_index);
                return false;
			}
			else {
				current_symbol = *s;
				current_index = next_index(current_index, current_k, reduce_factor);
				current_k = current_k / reduce_factor;
				current_lvl = current_lvl + 1;
			}
		}

		let mut sym = [0u8; 32 * AGGREGATE];
        for j in 0..AGGREGATE {
        	let temp: [u8; 32] = current_symbol[j].clone().into();
        	sym[j * 32 .. (j+1) * 32].copy_from_slice(&temp);
        }

        if dhash256(&sym) != self.coded_merkle_roots_hashes[(current_index as usize)] {
        	println!("Failed at level {} with symbol index {}.", current_lvl, current_index);
            false
        } else{
        	true
        }
    }

    //#[cfg(any(test, feature = "test-helpers"))]
	pub fn verify_base(&self, symbol: SymbolBase, index: u32, proof: &Vec<SymbolUp>) -> bool {
		let reduce_factor = ((AGGREGATE as f32) * self.rate) as u32;
		let mut hash_index = 0;
			// current base symbol is a systematic symbol
			if index <= self.block_size - 1 {
				hash_index = index % reduce_factor;
			}
			// current base symbol is a parity symbol
			else {
				hash_index = (index - self.block_size) % ((AGGREGATE as u32) -
                                                       reduce_factor) + reduce_factor;
			}

		if dhash256(&symbol) != proof[0][(hash_index as usize)]{
			    println!("Failed at base level with symbol index {}.", index);
                false
			}
			else {
				self.verify_up(proof[0], 1, 
					next_index(index, self.block_size, reduce_factor), &proof[1..].to_vec())
			}
		}


    //Verify that a malicious block producer does not do coding correctly, return true if the verification passes, or the coding is not correct
	pub fn verify_incorrect_coding(proof: Symbols, lvl: u32, index: Vec<u32>, merkle_proofs: Vec<Vec<SymbolUp>>, error_type: CodingErr) -> bool {
		match proof {
			Symbols::Base(err_symbols) => {
				// first check the Merkle proofs of all symbols in the incorrect-coding proof
				for i in 0..index {
					if !self.verify_base(err_symbols[i], index[i], &merkle_proofs[i]) {
						return true;
					}
				}
				if error_type == NotZero {

				} else {

				}
			}
			Symbols::Upper(err_symbols) => {

			}
		}

	}
}

impl fmt::Debug for BlockHeader {
	//Not quite sure what is this function trying to do.
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("BlockHeader")
			.field("version", &self.version)
			.field("previous_header_hash", &self.previous_header_hash.reversed())
			.field("merkle_root_hash", &self.merkle_root_hash.reversed())
			.field("time", &self.time)
			.field("bits", &self.bits)
			.field("nonce", &self.nonce)
			//.field("coded_merkle_roots_hashes", &self.coded_merkle_roots_hashes.reversed())
			.field("rate", &self.rate)
			.finish()
	}
}

impl From<&'static str> for BlockHeader {
	fn from(s: &'static str) -> Self {
		deserialize(&s.from_hex::<Vec<u8>>().unwrap() as &[u8]).unwrap()
	}
}

// Compute hash of the block header.
pub(crate) fn block_header_hash(block_header: &BlockHeader) -> H256 {
	dhash256(&serialize(block_header))
}

#[cfg(test)]
mod tests {
	use ser::{Reader, Error as ReaderError, Stream};
	//use super::BlockHeader;
	use super::*;

	#[test]
	#[ignore]
	fn test_block_header_stream() {
		let block_header = BlockHeader {
			version: 1,
			previous_header_hash: [2; 32].into(),
			merkle_root_hash: [3; 32].into(),
			time: 4,
			bits: 5.into(),
			nonce: 6,
			coded_merkle_roots_hashes: vec![H256::default();4].into(),
			rate: 0.25,
			block_size: 1024, 
		};

		let mut stream = Stream::default();
		stream.append(&block_header);

		let expected = vec![
			1, 0, 0, 0,
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
			4, 0, 0, 0,
			5, 0, 0, 0,
			6, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0.25, 0, 0, 0,
			1024, 0, 0,
		].into();

		assert_eq!(stream.out(), expected);
	}

	#[test]
	#[ignore]
	fn test_block_header_reader() {
		let buffer = vec![
			1, 0, 0, 0,
			2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
			3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
			4, 0, 0, 0,
			5, 0, 0, 0,
			6, 0, 0, 0,
		];

		let mut reader = Reader::new(&buffer);

		let expected = BlockHeader {
			version: 1,
			previous_header_hash: [2; 32].into(),
			merkle_root_hash: [3; 32].into(),
			time: 4,
			bits: 5.into(),
			nonce: 6,
		};

		assert_eq!(expected, reader.read().unwrap());
		assert_eq!(ReaderError::UnexpectedEnd, reader.read::<BlockHeader>().unwrap_err());
	}
}
