#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from easy1 import *
import differential_cryptanalysis_lib as dc_lib
from math import fabs, ceil
import random

# modify accordingly
def do_sbox(number):
    return s[number]

# modify accordingly
def do_inv_sbox(number):
    return s_inv[number]

# modify accordingly
def do_pbox(state):
    return pbox(state)

def main():

    NUM_P_C_PAIRS = 5000
    SBOX_BITS  = 6
    NUM_SBOXES = 6
    NUM_ROUNDS = 4
    MIN_PROB = 0.008
    MAX_BLOCKS_TO_BF = 4

    dc_lib.initialize(NUM_P_C_PAIRS,
                      SBOX_BITS,
                      NUM_SBOXES,
                      NUM_ROUNDS,
                      MIN_PROB,
                      MAX_BLOCKS_TO_BF,
                      do_sbox,
                      do_inv_sbox,
                      do_pbox)

    print('analizing cipher...')
    # there is no need to do this each time
    diff_characteristics = dc_lib.analize_cipher()
    if len(diff_characteristics) == 0:
        exit('no differential characteristic could be found!')

    print('\nbest differential characteristics:')
    # just for demonstration
    for i in range(10):
        try:
            print(diff_characteristics[i])
        except IndexError:
            break

    print('\nthe differential characteristic with the best probability will be used')
    # you may choose anyone you like
    diff_characteristic = diff_characteristics[0]

    # this will be different with another cipher
    key = random.getrandbits(18)
    key = (key << 18) | key

    # find which key bits we should obtain
    key_to_find = 0
    for block_num in diff_characteristic[2]:
        k = key >> ((NUM_SBOXES - (block_num-1) - 1) * SBOX_BITS)
        k = k & ((1 << SBOX_BITS) - 1)
        key_to_find = (key_to_find << SBOX_BITS) | k

    # generate the chosen-plaintexts and their ciphertexts
    # the 'encrypt' function might be different for you
    c_pairs = []
    p_diff = diff_characteristic[1]
    for p1 in range(NUM_P_C_PAIRS):
        c1 = encrypt(key, p1, NUM_ROUNDS)
        p2 = p1 ^ p_diff
        c2 = encrypt(key, p2, NUM_ROUNDS)
        c_pairs.append( [c1, c2] )

    print('\nbreaking cipher...\n')

    # obtain the hits given the ciphertexts pairs and the differential characteristic
    hits = dc_lib.get_hits(c_pairs, diff_characteristic)

    # get the key with the most hits
    maxResult, maxIdx = 0, 0
    for rIdx, result in enumerate(hits):
        if result > maxResult:
            maxResult = result
            maxIdx    = rIdx

    if maxIdx == key_to_find:
        print('Success!')
        bits_found = '{:b}'.format(maxIdx).zfill(len(diff_characteristic[2])*SBOX_BITS)
        bits_found = [bits_found[i:i+SBOX_BITS] for i in range(0, len(bits_found), SBOX_BITS)]

        blocks_num = list(diff_characteristic[2].keys())

        zipped = list(zip(blocks_num, bits_found))

        print('\nobtained key bits:')
        for num_block, bits in zipped:
            print('block {:d}: {}'.format(num_block, bits))

    else:
        print('Failure')

if __name__ == "__main__":
    main()
