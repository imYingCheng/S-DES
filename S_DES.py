#資料
IP = [2, 6, 3, 1, 4, 8, 5, 7]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
IP_INVERSE = [4, 1, 3, 5, 7, 2, 8, 6]
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
P4 = [2, 4, 3, 1]
S0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]

#將輸入的字串按照指定fixed_key的順序重新排列
def permutate(original, fixed_key):
    new = ""
    for i in fixed_key:
        new += original[i - 1]
    return new

#回傳bits的左半部
def left_half(bits):
    return bits[:int(len(bits)/2)]

#回傳bits的右半部
def right_half(bits):
    return bits[int(len(bits)/2):]

#將bits左移一次（循環左移）
def shift(bits):
    rotated_left_half = left_half(bits)[1:] + left_half(bits)[0]
    rotated_right_half = right_half(bits)[1:] + right_half(bits)[0]
    return rotated_left_half + rotated_right_half

#將傳入的bits和key做XOR運算
def xor(bits, key):
    new = ''
    for bit, key_bit in zip(bits, key):
        new += str(((int(bit) + int(key_bit)) % 2))
    return new

#回傳bits在指定s-box內所對應的值
def S_Box(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return '{0:02b}'.format(sbox[row][col])

#用輸入的KEY計算key1, P10 -> LS-1 -> P8
def key1(KEY):
    p10 = permutate(KEY, P10)
    ls1 = shift(p10)
    (ls1_left, ls1_right) = (left_half(ls1), right_half(ls1))
    p8 = permutate(ls1, P8)
    return (p10, ls1_left, ls1_right, p8), p8

#用輸入的KEY計算key2, P10 -> LS-3 -> P8
def key2(KEY):
    p10 = permutate(KEY, P10)
    ls2 = shift(shift(shift(p10)))
    (ls2_left, ls2_right) = (left_half(ls2), right_half(ls2))
    p8 = permutate(ls2, P8)
    return (ls2_left, ls2_right, p8), p8

#加解密用的round function
def fk(bits, key):
    (L, R) = (left_half(bits), right_half(bits))
    ep = permutate(R, EP)
    xor_bits = xor(ep, key)
    s0 = S_Box(left_half(xor_bits), S0)
    s1 = S_Box(right_half(xor_bits), S1)
    s_box = s0 + s1
    p4 = permutate(s_box, P4)
    left_fk_result = xor(p4, L)
    fk_result = xor(p4, L) + right_half(bits)
    return (ep, xor_bits, s0, s1, p4, fk_result), left_fk_result

#根據plaintext和KEY執行加密
def encrypt(P, KEY):
    ip = permutate(P, IP)
    (key_1_inter_results, key_1) = key1(KEY)
    (fk_1_inter_results, fk_1) = fk(ip, key_1)
    SW = right_half(ip) + fk_1
    (key_2_inter_results, key_2) = key2(KEY)
    (fk_2_inter_results, fk_2) = fk(SW, key_2)
    C = permutate(fk_2 + fk_1, IP_INVERSE)
    return fk_1_inter_results, fk_2_inter_results, (ip, fk_1, SW, fk_2, C), C, key_1, key_2

#根據ciphertext和KEY執行解密
def decrypt(C, KEY):
    ip = permutate(C, IP)
    (key_2_inter_results, key_2) = key2(KEY)
    (fk_2_inter_results, fk_2) = fk(ip, key_2)
    SW = right_half(ip) + fk_2
    (key_1_inter_results, key_1) = key1(KEY)
    (fk_1_inter_results, fk_1) = fk(SW, key_1)
    P = permutate(fk_1 + fk_2, IP_INVERSE)
    return fk_1_inter_results, fk_2_inter_results, (ip, fk_2, SW, fk_1, P), P, key_1, key_2

#確認text為二進位數
def check_binary(text):
    for t in text:
        if t != '0' and t != '1':
            print("Please enter binary number!")
            return False
    return True
