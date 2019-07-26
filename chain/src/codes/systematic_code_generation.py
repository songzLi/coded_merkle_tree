import numpy as np
import pickle


def GE(H_origin, d=8, check=True):
    p, n = np.shape(H_origin)
    k = n - p
    H = np.copy(H_origin)
    empty_pivot = []
    # Step-1: transform the left p columns into an identity matrix through GE
    for pivot in range(p):
        if pivot % 100 == 0:
            print(pivot)
        # find the pivot
        found = False
        for col in range(pivot, n):  # scan all the columns from column-pivot
            if found:
                break
            row = (H[pivot:, col] != 0).argmax()  # find the first 1
            # the above code will return 0 if there is no one.
            # so idx = 0 can either mean the 0-th entry is 1 or there is no 1.
            if H[pivot + row, col] == 1:  # check that we find a 1
                found = True
                row += pivot
                if not row == pivot:  # row swap
                    H[[pivot, row]] = H[[row, pivot]]
                if not col == pivot:  # column swap, also swap the origin
                    H[:, [pivot, col]] = H[:, [col, pivot]]
                    H_origin[:, [pivot, col]] = H_origin[:, [col, pivot]]
                break
        if found:  # XOR elimination
            rows = list(np.where(H[:, pivot] > 0)[0])
            rows.remove(pivot)
            for row in rows:
                H[row] = np.bitwise_xor(H[row], H[pivot])
        else:  # found an empty pivot
            empty_pivot.append(pivot)
    # Step-2: add linear independent rows for the empty pivots
    for pivot in empty_pivot:
        vec = np.zeros(n, dtype=bool)
        vec[pivot] = np.bool(1)
        indices = np.random.permutation(k)
        vec[indices[:d - 1] + p] = np.bool(1)
        # update origin
        H_origin = np.vstack([H_origin, vec])
        # GE on A
        H[pivot] = vec
        for row in range(p):
            if (not row == pivot) and H[row][pivot] == 1:
                H[row] = np.bitwise_xor(H[row], H[pivot])

    # Step-3: roll the left p columns to the right,
    # so that the right is full rank, which will adimit a systematic code.
    H = np.roll(H, k, axis=1)
    H_origin = np.roll(H_origin, k, axis=1)
    # Step-4: optional, double-check that we are correct
    if check:
        for pivot in range(p):
            assert np.sum(H[pivot, (k + pivot): n]) == 1
            assert H[pivot, k + pivot] == 1

    return H, H_origin


def matrix_to_list(H_encode, H_decode):
    # this function read the matrix and store:
    # parity_symbols: ps[i] lists the symbols involved in parity-i.
    # symbols_parity: sp[i] lists the parities symbol-i involves.
    # It also stores parity_symbols as a txt file.
    p, n = np.shape(H_encode)
    p_extended, _ = np.shape(H_decode)
    k = n - p
    parity_symbols = []
    symbol_parities = []
    for row in range(p_extended):
        parity_symbols.append(list(np.nonzero(H_decode[row])[0]))
    for col in range(n):
        symbol_parities.append(list(np.nonzero(H_decode[:, col])[0]))
    result = {}
    result['parities'] = parity_symbols
    result['symbols'] = symbol_parities
    with open('symbols_and_parities_k=' + str(k) + '.pickle', 'wb') as handle:
        pickle.dump(result, handle)
    print('saved', 'symbols_and_parities_k=' + str(k) + '.pickle')

    f = open("k=" + str(k) + "_decode.txt", "w")
    for symbols in parity_symbols:
        for s in symbols:
            if not s == symbols[-1]:  # add space if it is not the last entry
                f.write(str(s) + ' ')
            else:
                f.write(str(s))
        # start a new line if it is not the last line
        if not symbols == parity_symbols[-1]:
            f.write('\n')
    f.close()
    print("saved", "k=" + str(k) + "_decode.txt")

    f = open("k=" + str(k) + "_encode.txt", "w")
    for r in range(p):
        row = H_encode[r]
        symbols = list(np.nonzero(row > 0)[0])
        for s in symbols:
            if not s == symbols[-1]:  # add space if it is not the last entry
                f.write(str(s) + ' ')
            else:
                f.write(str(s))
        # start a new line if it is not the last line
        if not symbols == parity_symbols[-1]:
            f.write('\n')
    f.close()
    print('saved', 'k=' + str(k) + '_encode.txt')


def txt_to_matrix(file_name):
    # this function reads the txt description of the parity matrix
    # and realizes it.
    # row-i of the txt is the list of symbols involved in parity-i.
    raw = open(file_name, 'r').read()
    parties_lines = raw.splitlines()
    p = len(parties_lines)
    n = np.int(p * 4 / 3)
    H_origin = np.zeros((p, n), dtype=bool)
    for row in range(p):
        idx_list = parties_lines[row].split()
        for idx in idx_list:
            H_origin[row, np.int(idx)] = np.bool(1)
    return H_origin


def txt_to_sys_code(file_name):
    H_origin = txt_to_matrix(file_name)
    H_encode, H_decode = GE(H_origin, d=8)
    matrix_to_list(H_encode, H_decode)


# txt_to_sys_code('newexample4.txt')
# txt_to_sys_code('newexample16.txt')
# txt_to_sys_code('newexample64.txt')
txt_to_sys_code('newexample256.txt')
