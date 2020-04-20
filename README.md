# Differential-Cryptanalysis

## What is this?

This repository presents a differential cryptanalysis library that tries to break SPN ciphers in a fully automatic way.  

Right now it only supports SPNs with just one type of sbox, but extending it to support multiple types of sbox should be easy.


## How does it work?

Glad you asked, the algorithm is very simple.  

### First

We compute the differential characteristics table of the sbox. There is nothing fancy about this.  
All the characteristics with more than 0 hits are kept and sorted in descending order.

### Second

This step is identical to [this](https://github.com/physics-sp/Linear-Cryptanalysis) repository.


### Third

We choose one differential characteristic of the entire cipher from the previous step (normally the one with the highest probability).  

Now, we generate multiple plaintext pairs with the correct differential and encrypt them. Then we use the chosen differential characteristic to obtain bits of the last round key. (again, nothing fancy here, just normal differential cryptanalysis.)

## How to use

### Example  
There are two examples. The `break-basic_SPN.py` and the `break-easy1.py` file.  

### Functions you may want to use

`initialize()`  
Initializes the library with the SPN's properties.  

`create_diff_table()`  
Creates the differential characteristics table for the sbox.  

`get_diff_characteristics(diff_chr_table)`  
Returns all possible differential characteristics of the entire cipher (that respect the MAX_BLOCKS_TO_BF filter).  

`analize_cipher()`  
Creates the table (calling `create_diff_table`) and sorts it (if it is longer than 50 rows, keeps the best 50).  
Then, calls `get_diff_characteristics` and sorts the results (deleting the items that have a probability lower than MIN_PROB) and returns the sorted list.  

`get_hits(c_pairs, diff_characteristic)`  
Returns a list of hits. The index of the hit is the key used to obtain it.

## Considerations

Keep in mind that you might use multiple differential characteristics to recover different bits of the last round key.  

If the differential characteristics table is bigger than max_size rows, the library keeps the best max_size, you might want to proceed differently.  

## More information

To learn about differential cryptanalysis, read [this](https://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf) awesome paper by Howard M. Heys and read *Modern Cryptanalysis: Techniques for Advanced Code Breaking* by Christopher Swenson.


## Credit

Thanks to [hkscy](https://github.com/hkscy/Basic-SPN-cryptanalysis) for the great *Basic SPN* implementation.
