#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from math import fabs, ceil
import multiprocessing
import concurrent.futures

from basic_SPN import *

initialized = False

# I know this is ugly
def initialize(num_p_c_pairs, sbox_bits , num_sboxes, num_rounds, min_prob, max_blocks_to_bf, do_sbox_param, do_inv_sbox_param, do_pbox_param):
    global NUM_C_PAIRS, SBOX_BITS , NUM_SBOXES, NUM_ROUNDS, MIN_PROB, MAX_BLOCKS_TO_BF, do_sbox, do_inv_sbox, do_pbox, initialized
    NUM_C_PAIRS = num_p_c_pairs
    SBOX_BITS = sbox_bits
    NUM_SBOXES = num_sboxes
    NUM_ROUNDS = num_rounds
    MIN_PROB = min_prob
    MAX_BLOCKS_TO_BF = max_blocks_to_bf
    do_sbox = do_sbox_param
    do_inv_sbox = do_inv_sbox_param
    do_pbox = do_pbox_param
    initialized = True

def apply_mask(value, mask):
    #retrieve the parity of mask/value
    interValue = value & mask
    total = 0
    while interValue > 0:
        temp = interValue & 1
        interValue = interValue >> 1
        if temp == 1:
            total = total ^ 1
    return total

def create_diff_table():
    # Calculate the maximum value / differential
    ssize = 1 << SBOX_BITS
    # Generate the matrix of differences, starting
    # at all zeros
    table = []
    for i in range(ssize):
        table.append([0 for j in range(ssize)])
    # Take every possible value for the first plaintext
    for x1 in range(0, ssize):
        # Calculate the corresponding ciphertext
        y1 = do_sbox(x1)
        # Now, for each possible differential
        for dx in range(1, ssize):
            # Calculate the other plaintext and ciphertext
            x2 = x1 ^ dx
            y2 = do_sbox(x2)
            # Calculate the output differential
            dy = y1 ^ y2
            # Increment the count of the characteristic
            # in the table corresponding to the two
            # differentials
            table[dx][dy] += 1

    return table

# only keeps the dx and dy pairs that have more than zero hits
def reduce_table(table):
    ssize = 1 << SBOX_BITS

    new_table = []
    for dx in range(ssize):
        for dy in range(ssize):
            prob = (table[dx][dy]/ssize) * 100
            if prob >= MIN_PROB:
                new_table.append( [dx, dy, table[dx][dy]/ssize] )

    # each element consist in dx, dy and the probability
    return new_table

# from an sbox and the "output" of a bias y,
# calculate which sboxs will be reached and in which bits
def get_destination(num_sbox, y):
    # pass 'y' through the permutation
    offset = (NUM_SBOXES - (num_sbox-1) - 1) * SBOX_BITS
    Y = y << offset
    # do_pbox is supposed to transpose the state, make sure is well defined!
    permuted = do_pbox(Y)

    sboxes_reached = {}
    # sboxes go from 1 to NUM_SBOXES from left to right
    # bits go from 1 to SBOX_BITS from left to right
    for sbox in range(1, NUM_SBOXES + 1):
        for bit in range(SBOX_BITS):
            bits_offset = ((NUM_SBOXES - (sbox-1) - 1) * SBOX_BITS) + bit
            # if 'sbox' has a 1 in the position 'bit' then take note of that
            if permuted & (1 << bits_offset) != 0:
                if sbox not in sboxes_reached:
                    sboxes_reached[sbox] = []
                sboxes_reached[sbox].append(SBOX_BITS - bit)
    # return which sboxes where reached and in which bit
    return sboxes_reached

# convert a list of bits to an integer
def bits_to_num(inputbits):
    Y_input = 0
    for input_pos in inputbits:
        Y_input |= 1 << (SBOX_BITS - input_pos)
    return Y_input

# convert an integer to a list of it's bits
def num_to_bits(num):
    bits = []
    for index in range(SBOX_BITS):
        if (1 << index) & num > 0:
            bits.append( SBOX_BITS - index )
    return bits

# this function eliminates the differential characteristics that have
# a probability below the MIN_PROB threshold and then sorts the results
def sort_diff_characteristics(diff_characteristics):
    if not initialized: exit('initialize the library first!')

    sorted_diff_characteristics = []
    for diff_characteristic in diff_characteristics:
        probabilities = diff_characteristic['probabilities']

        # calculate the resulting probability
        resulting_probability = 1
        for _, _, prob in probabilities:
            resulting_probability *= prob
        resulting_probability *= 100

        # construct the element of the list resulting list
        x, y, _ = probabilities[0]
        _, num_sbox = diff_characteristic['start']
        dx = x << ((NUM_SBOXES - (num_sbox-1) - 1) * SBOX_BITS)
        entry = [resulting_probability, dx, diff_characteristic['state']]
        # keep the entry only if has a probability grater than MIN_PROB
        if resulting_probability > MIN_PROB:
            sorted_diff_characteristics.append( entry )

    # sort and return the result
    sorted_diff_characteristics = sorted(sorted_diff_characteristics, key=lambda elem: fabs(elem[0]), reverse=True)
    return sorted_diff_characteristics

# calculate all the possible differential characteristics given the table
def get_diff_characteristics(diff_chr_table, current_states=None, depth=1):
    if not initialized: exit('initialize the library first!')

    # run for NUM_ROUNDS - 1 times
    if depth == NUM_ROUNDS:
        # delete elements that involve more than MAX_BLOCKS_TO_BF final sboxes
        current_states = [elem for elem in current_states if len(elem['state']) <= MAX_BLOCKS_TO_BF]
        if len(current_states) == 0:
            exit('No differential characteristic found! May be MIN_PROB is too high or MAX_BLOCKS_TO_BF too low.')
        # return the differential characteristics that reach to no more than MAX_BLOCKS_TO_BF sboxes
        return current_states

    # at the beginnig, only one sbox can be chosen
    # (this could be done differently)
    if depth == 1:
        # for each bias and each sbox, calculate which sboxes are reached (in the lower layer)
        # this will be the next step's new initial state
        current_states = []
        for x, y, bias in diff_chr_table:

            for num_sbox in range(1, NUM_SBOXES + 1):

                sboxes_reached = get_destination(num_sbox, y)

                entry = {}
                entry['start']  = [depth, num_sbox]
                entry['probabilities'] = [[x, y, bias]]
                entry['state']  = sboxes_reached

                current_states.append( entry )
        # call the function recursevely with the new current state and new depth
        return get_diff_characteristics(diff_chr_table, current_states, depth + 1)

    else:
        # for each set of possible states it will do the following:
        #   for each sbox that we last reached,
        #   it will calculate all possible moves according to the bias table.
        #   then it will calculate all possible the combinations of choices
        # this set of combinations, will be our next 'current_states'
        # lastly, it will call itself recursevely
        next_states = []
        for current_state in current_states:

            curr_pos = current_state['state']

            # calculate all possible moves from 'curr_sbox'
            total_combinations = 1
            start_sboxes = {}
            possible_step_per_sbox = {}
            num_possible_step_per_sbox = {}
            num_start_sboxes = 0
            for curr_sbox in curr_pos:

                inputs  = curr_pos[curr_sbox]
                Y_input = bits_to_num(inputs)

                possible_steps = []

                # only use the biases which input matches the current sbox
                possible_biases = [ elem for elem in diff_chr_table if elem[0] == Y_input ]
                for x, y, bias in possible_biases:

                    sboxes_reached = get_destination(curr_sbox, y)

                    step = {'to': sboxes_reached, 'path': [x, y, bias]}

                    possible_steps.append(step)


                if len(possible_steps) > 0:
                    total_combinations *= len(possible_steps)
                    possible_step_per_sbox[curr_sbox] = possible_steps
                    start_sboxes[num_start_sboxes] = curr_sbox
                    num_possible_step_per_sbox[curr_sbox] = len(possible_steps)
                    num_start_sboxes += 1

            if total_combinations == 0:
                continue

            # combine all the possible choises of each sbox in all possible ways
            # for example, if there are 2 sboxes and each has 4 possible moves
            # then calculate all 16 (4x4) possible combinations.


            possible_steps_combinations = []

            for comb_num in range(total_combinations):
                new_comb = []
                new_comb.append( possible_step_per_sbox[start_sboxes[0]][comb_num % num_possible_step_per_sbox[start_sboxes[0]]] )
                for sbox in start_sboxes:
                    if sbox == 0:
                        continue
                    real_sbox = start_sboxes[sbox]

                    mod = 1
                    for prev_sbox in range(sbox):
                        mod *= num_possible_step_per_sbox[start_sboxes[prev_sbox]]

                    index = (comb_num / mod) % num_possible_step_per_sbox[real_sbox]
                    index = int(index)

                    new_comb.append( possible_step_per_sbox[real_sbox][index] )
                possible_steps_combinations.append(new_comb)


            # now, for each combination, check to which sboxes we reached and what are their inputs
            # this will be the next state
            for possible_step in possible_steps_combinations:

                # save the first sbox and the previous biases
                entry = {}
                entry['start'] = current_state['start']
                entry['probabilities'] = current_state['probabilities'].copy()
                entry['state'] = {}

                # add the new biases
                for elem in possible_step:
                    entry['probabilities'].append( elem['path'] )

                    # add the final sboxes and their inputs
                    for destination in elem['to']:
                        if destination not in entry['state']:
                            entry['state'][destination] = []

                        new_bits = elem['to'][destination]
                        entry['state'][destination] += new_bits


                # calculate the resulting Probability
                biases = entry['probabilities']
                resulting_bias = 1
                for _, _, bias in biases:
                    resulting_bias *= bias
                resulting_bias *= 100
                if resulting_bias >= MIN_PROB:
                    # update the next_states
                    next_states.append( entry )


        return get_diff_characteristics(diff_chr_table, next_states, depth + 1)

def analize_cipher():
    if not initialized: exit('initialize the library first!')

    # analize the sbox and create the bias table
    table = create_diff_table()
    table = reduce_table(table)
    table_sorted = sorted(table, key=lambda elem: fabs(elem[2]), reverse=True)

    # take the best max_size results (so that the following algorithm finishes quickly)
    max_size = 1000
    table_len = len(table_sorted)
    if table_len > max_size:
        print('\n[*] reducing bias table size from {:d} to {:d}\n'.format(table_len, max_size))
        table_sorted = table_sorted[:max_size]

    # calculate all possible differential characteristics
    diff_characteristics = get_diff_characteristics(table_sorted)
    # sort the list from the best approximations to the worst
    diff_characteristics_sorted = sort_diff_characteristics(diff_characteristics)
    # return the sorted list of approximations
    return diff_characteristics_sorted

# obtain the difference between the two ciphertexts
def get_diff(c1, c2, key, diff_characteristic):
    _, _, c_data = diff_characteristic

    # for each final sbox, get the according ciphertext block
    diff_total = 0
    i = len(c_data) - 1
    for c_block_num in c_data:
        # obtain the desired difference
        c_bits = c_data[c_block_num]
        c_diff = bits_to_num(c_bits)

        # get the c1 block
        ct1 = c1 >> ((NUM_SBOXES - c_block_num) * SBOX_BITS)
        ct1 = ct1 & ((1 << SBOX_BITS) - 1)
        # get the c2 block
        ct2 = c2 >> ((NUM_SBOXES - c_block_num) * SBOX_BITS)
        ct2 = ct2 & ((1 << SBOX_BITS) - 1)

        # get the key block that corresponds with the sbox
        k = key >> (i * SBOX_BITS)
        k = k & ((1 << SBOX_BITS) - 1)

        # xor the key and the ciphertext to get v (the sbox output)
        v1 = ct1 ^ k
        v2 = ct2 ^ k

        # get the sbox input
        # do_inv_sbox is supposed to calculate the inverse of the substitution, make sure is well defined!
        u1 = do_inv_sbox(v1)
        u2 = do_inv_sbox(v2)

        # add the xor between the actual difference and the desired difference
        diff_total += u1 ^ u2 ^ c_diff

        i -= 1

    # return the result of the full xor
    return diff_total

def get_hits_for_key_space(keystart, keyend, c_pairs, diff_characteristic):

    try:
        hits = [0] * (keyend - keystart)
    except OverflowError:
        exit('the amount of key bits to brute force is too large.')

    # get the result of the aproximation for each possible key
    for key in range(keystart, keyend):
        for c1, c2 in c_pairs:
            diff = get_diff(c1, c2, key, diff_characteristic)
            if diff == 0:
                hits[keystart - key] += 1

    result = {'start': keystart, 'end': keyend, 'hits': hits}
    return result

def get_hits(c_pairs, diff_characteristic):
    if not initialized: exit('initialize the library first!')

    # calculate how many key bits must be brute forced
    key_bits = len(diff_characteristic[2]) * SBOX_BITS
    try:
        # get the key's maximum size
        key_max  = 1 << key_bits
    except MemoryError:
        exit('the amount of key bits to brute force is too large.')

    num_cores = multiprocessing.cpu_count()

    sub_key_space = key_max // num_cores

    bias_lists = []

    # run in num_cores threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_cores) as executor:

        future_list = []
        # divide the key space into num_cores parts
        for core in range(num_cores):
            start = sub_key_space * core
            end   = start + sub_key_space

            future = executor.submit(get_hits_for_key_space, start, end, c_pairs, diff_characteristic)
            future_list.append(future)

        # get the result for each thread
        for future in concurrent.futures.as_completed(future_list):
            bias_lists.append(future.result())

    try:
        hits = [0] * key_max
    except OverflowError:
        exit('the amount of key bits to brute force is too large.')

    # join all the results
    for result in bias_lists:
        start = result['start']
        end   = result['end']
        array = result['hits']
        for hit in range(start, end):
            hits[hit] = array[start - hit]

    return hits

if __name__ == "__main__":
    print('import this in your script')
