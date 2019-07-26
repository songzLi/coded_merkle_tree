# Chain

In this crate, we implement _coded Merkle tree_ (CMT) for parity Bitcoin blocks.

## Overview
We add the following modules to impplement CMT.
* Coded Merkle Roots
* Decoder

We modify the following modules of parity Bitcoin block to reflect the addition of CMT.
* Block 
* Block Header

## Crate Content

### Coded Merkle Tree (coded_merkle_roots.rs)


### Decoder (decoder.rs)


### Block (block.rs)
A relatively straight forward implementation of the data structure described above. A `block` is a rust `struct`. It implements the following traits:
* ```From<&'static  str>```: this trait takes in a string and outputs a `block`. It is implemented via the `from` function which deserializes the received string into a `block` data structure. Read more about serialization [here](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch06.asciidoc#transaction-serializationoutputs) (in the context of transactions).

The `block` has a few methods of its own. The entirety of these are simple getter methods.

### Block Header (block_header.rs)
A relatively straight forward implementation of the data structure described above. A `block header` is a rust `struct`. It implements the following traits:
* ```From<&'static  str>```: this trait takes in a string and outputs a `block`. It is implemented via the `from` function which deserializes the received string into a `block` data structure. Read more about serialization [here](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch06.asciidoc#transaction-serializationoutputs) (in the context of transactions).
* `fmt::Debug`: this trait formats the `block header` struct for pretty printing the debug context -- ie it allows the programmer to print out the context of the struct in a way that makes it easier to debug. Once this trait is implemented, you can do:
```rust
println!("{:?}", some_block_header);
```
Which will print out:
```
Block Header {
    version: VERSION_VALUE,
    previous_header_hash: PREVIOUS_HASH_HEADER_VALUE,
    merkle_root_hash: MERKLE_ROOT_HASH_VALUE,
    time: TIME_VALUE,
    bits: BITS_VALUE,
    nonce: NONCE_VALUE,
}
```
The `block header` only has a single method of its own, the `hash` method that returns a hash of itself.

### Constants (constants.rs)
There are a few constants included in this crate. Since these are nicely documented, documenting them here would be redundant. [Here](https://doc.rust-lang.org/rust-by-example/custom_types/constants.html) you can read more about constants in rust.

### Tests (main.rs)





Various reference LDPC codes are included in the LDPC_codes folder. Each code has a encode file and a decode file.



### Read and Hash (read_and_hash.rs)
This is a small file that deals with the reading and hashing of serialized data, utilizing a few nifty rust features. 

First, a `HashedData` struct is defined over a generic T. Generics in rust work in a similar way to generics in other languages. If you need to brush up on generics, [read here](https://doc.rust-lang.org/1.8.0/book/generics.html). This data structure stores the data for a hashed value along with the size (length of the hash in bytes) and the original hash.

Next the `ReadAndHash` trait is defined. Traits in rust define abstract behaviors that can be shared between many different types. For example, let's say I am writing some code about food. To do this, I might want to create an `Eatable` trait that has a method `eat` describing how to eat this food (borrowing an example from the [New Rustacean podcast](https://newrustacean.com/)). To do this, I would define the trait as follows:
```rust
pub trait Eatable {
	fn eat(&self) -> String;
}
```
Here I have defined a trait along with a method signature that must be implemented by any type that implements this trait. For example, let's say I define a candy type that is eatable:
```rust
struct Candy {
   flavor: String,
}

impl Eatable for Candy {
	fn eat(&self) -> String {
    	format!("Unwrap candy and munch on that {} goodness.", &self.flavor)
    }
}

// Create candy and eat it
let candy = Candy { flavor: chocolate };
prinln!("{}", candy.eat()); // "Unwrap candy and munch on that chocolate goodness."
```

Now let's take this one step further. Let's say we want to recreate Eatable so that the eat function returns a `Compost` type with generic T where presumably T is some type that is `Compostable` (another trait). Now here, it is important that we only return `Compostable` types because only `Compostable` foods can be made into Compost. Thus, we can recreate the `Eatable` trait, this time limiting what types can implement it to those that also implement the `Compostable` trait using the where keyword (note this is called a bounded trait):
```rust
pub trait Eatable {
	fn eat<T>(&self) -> Compost<T> where T: Compostable;
}

pub trait Compostable {} // Here Compostable is a marker trait

struct Compost<T> {
	compostable_food: T,
}

impl<T> Compost<t> {
	fn celebrate() {
    	println!("Thank you for saving the earth!");
    }
}
```
So, let's now redefine `Candy`:
```rust
struct Candy {
   flavor: String,
}

impl Compostable for Candy {}


impl Eatable for Candy {
	fn eat<T>(&self) -> Compost<T> where T: Compostable{
    	Compost { compostable_food: format("A {} candy", &self.flavor) }
    }
}

// Create candy and eat it
let candy = Candy { flavor: chocolate };
let compost = candy.eat();
compost.celebrate(); // "Thank you for saving the earth!"
```

If this example doesn't quite make sense, I recommend checking out the [traits chapter](https://doc.rust-lang.org/book/second-edition/ch10-02-traits.html) in the Rust Book.

Now that you understand traits, generics, and bounded traits, let's get back to `ReadAndHash`. This is a trait that implements a `read_and_hash<T>` method where T is `Deserializable`, hence it can be deserialized (which as you might guess is important since the input here is a serialized string). The output of this method is a Result (unfamiliar with Results in rust... [read more here](https://doc.rust-lang.org/std/result/)) returning the `HashedData` type described above.

Finally, the `ReadAndHash` trait is implemented for the `Reader` type. You can read more about the `Reader` type in the serialization crate.

### Transaction (transaction.rs)
As described above, there are four structs related to transactions defined in this file:
* OutPoint 
* TransactionInput 
* TransactionOutput 
* Transaction 

The implementations of these are pretty straight forward -- a majority of the defined methods are getters and each of these structs implements the `Serializable` and `Deserializable` traits.

A few things to note:
* The `HeapSizeOf` trait is implemented for `TransactionInput`, `TransactionOutput`, and `Transaction`. It has the method `heap_size_of_children` which calculates and returns the heap sizes of various struct fields.
* The `total_spends` method on `Transaction` calculates the sum of all the outputs in a transaction.


### Merkle Root (merkle_root.rs)
The main function in this file is the function that calculates the merkle root (a filed on the block header struct). This function has two helper functions:
* **concat**: takes two values and returns the concatenation of the two hashed values (512 bit)
* **merkle_root_hash**: hashes the 512 bit hash of two concatenated values

Using these two functions, the merkle root function takes a vector of values and calculates the merkle root row-by-row (a row being the level of a binary tree). Note, if there is an uneven number of values in the vector, the last value will be duplicated to create a full tree.

### Indexed
There are indexed equivalents of `block`, `block header`, and `transaction`:
* indexed_block.rs
* indexed_header.rs
* indexed_transaction.rs

These are essentially wrappers around the "raw" data structures with the following:
* methods to convert to and from the raw data structures (i.e. block <-> indexed_block)
* an equivalence method to compare equality against other indexed structures (specifically the PartialEq trait)
* a deserialize method
