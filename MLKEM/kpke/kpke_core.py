#K-PKE実装
#n=8 q=17 k=2 の実装例(簡略版)
from ..utils import hash_utils
from ..utils import poly_utils

#パラメータ
n = 8 #多項式の次数
q = 17 #係数の法
k = 2 #多項式の数 (k=eta)
eta = k
psi = pow(3, (q-1) // n, q) #n次の原始根
psi_rev = pow(psi, -1, q) #(ζ^-1)

#K-PKE鍵生成
def k_pke_keygen(seed: bytes) -> tuple:
    #入力：32バイトの乱数
    #出力：公開鍵(ek_PKE), 秘密鍵(dk_PKE)

    #1.乱数生成 (p,S)
    p,S = hash_utils.hash_G(seed,k)

    #2.公開鍵行列 ntt_A (k x k)生成
    ntt_A = [[0] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            input_data = p + j.to_bytes(1, 'little') + i.to_bytes(1, 'little')
            ntt_A[i][j] =poly_utils.sample_ntt(input_data) #n次元多項式の係数リストを生成
            
    #3.秘密鍵ベクトル s と誤差ベクトル e の生成
    nonce = 0
    s = [0] * k
    for i in range(k):
        s[i] = poly_utils.sample_poly_cbd(hash_utils.prf(S, eta, nonce), eta) #乱数を生成し、n次元多項式のリストを生成
        nonce += 1
    
    e = [0] * k
    for i in range(k):
        e[i] = poly_utils.sample_poly_cbd(hash_utils.prf(S, eta, nonce), eta) #乱数を生成し、n次元多項式のリストを生成
        nonce += 1

    #4.NTT変換
    ntt_vec_s = [poly_utils.NTT(poly, psi) for poly in s]
    ntt_vec_e = [poly_utils.NTT(poly, psi) for poly in e]

    #5.公開鍵　b の生成
    # b = ntt_A * ntt_vec_s + ntt_vec_e 
    b = [0] * k
    for i in range(k):
        term_ntt = [0] * n
        for j in range(k):
            prod = poly_utils.poly_mul_ntt(ntt_A[i][j], ntt_vec_s[j]) #リスト同士の乗算
            term_ntt = poly_utils.poly_add(term_ntt, prod)
        b[i] = poly_utils.poly_add(term_ntt, ntt_vec_e[i])

    #6.エンコード
    encoded_b = []
    for i in range(k):
        encoded_part = poly_utils.ByteEncode(b[i], 5) #n次元多項式の係数リストからバイト列を生成
        encoded_b.append(encoded_part)
    
    encoded_s = []
    for i in range(k):
        encoded_part = poly_utils.ByteEncode(ntt_vec_s[i], 5)
        encoded_s.append(encoded_part)

    #7.鍵ペアの生成

    # 10 bytes + 32 bytes = 42 bytes
    ek_PKE = b''.join(encoded_b) + p 
    # 10 bytes
    dk_PKE = b''.join(encoded_s)  

    return (ek_PKE,dk_PKE)

#K-PKE暗号化
def k_pke_enc(ek_PKE: bytes, m:bytes, r:bytes) -> bytes:
    #入力：公開鍵(ek_PKE),メッセージ(m,1バイト),乱数(r,32バイト)
    #出力：暗号文(c)

    #1.公開鍵のデコード
    p = ek_PKE[-32:]
    encorded_b = ek_PKE[:-32]
    b = poly_utils.ByteDecode(encorded_b, 5, k) #バイト列からk個のn次元多項式の(0,q-1)範囲の整数リストを返す

    #2.公開鍵行列 ntt_A (k x k)再現(生成)
    ntt_A = [[0] * k for _ in range(k)]
    for i in range(k):
        for j in range(k):
            input_data = p + j.to_bytes(1, 'little') + i.to_bytes(1, 'little')
            ntt_A[i][j] =poly_utils.sample_ntt(input_data) #n次元多項式の係数リストを生成

    #3.一時乱数ベクトル y と誤差ベクトル e1 を生成
    y = [0] * k
    nonce = 0
    for i in range(k):
        y[i] = poly_utils.sample_poly_cbd(hash_utils.prf(r, eta, nonce), eta) #n次元多項式の係数リストを生成
        nonce += 1
    
    e1 = [0] * k
    for i in range(k):
        e1[i] = poly_utils.sample_poly_cbd(hash_utils.prf(r, eta, nonce), eta) 
        nonce += 1

    #4.誤差多項式 e2 を生成
    e2 = poly_utils.sample_poly_cbd(hash_utils.prf(r, eta, nonce), eta)

    #5.NTT変換
    ntt_vec_y = [poly_utils.NTT(poly, psi) for poly in y]

    #6.ベクトル U の生成
    #U = ntt_A * ntt_vec_y + e1
    U = [0] * k
    for i in range(k):
        term_ntt = [0] * n
        for j in range(k):
            prod = poly_utils.poly_mul_ntt(ntt_A[i][j], ntt_vec_y[j]) #リスト同士の乗算
            term_ntt = poly_utils.poly_add(term_ntt, prod)
        U[i] = poly_utils.poly_add(term_ntt, e1[i])
    
    #7.メッセージ m を多項式化
    μ_poly_list = poly_utils.ByteDecode(m, 1, 1) #n次元の多項式の{0,1}の係数リストを生成
    μ = poly_utils.Decompress(μ_poly_list[0], 1) #0 => 0 , 1 =>（q + 1）/2 の範囲に変換

    #8.暗号文 V の生成
    #V = b * ntt_vec_y + e2 + μ
    term_ntt = [0] * n
    for i in range(k):
        prod = poly_utils.poly_mul_ntt(b[i], ntt_vec_y[i])
        term_ntt = poly_utils.poly_add(term_ntt, prod)
    V = poly_utils.poly_add(term_ntt, poly_utils.poly_add(e2, μ)) #n次元の多項式の係数リストを生成

    #9.エンコード
    u = []
    for i in range(k):
        compressed_U = poly_utils.Compress(U[i], 1) #(0~q-1)表現から{0,1}表現の係数リストを生成
        encorded_U = poly_utils.ByteEncode(compressed_U, 1) #バイト列生成
        u.append(encorded_U)

    v = []
    compressed_V = poly_utils.Compress(V, 1) #(0~q-1)表現から{0,1}表現の係数リストを生成
    v = poly_utils.ByteEncode(compressed_V, 1) #バイト列生成
    
    c = b''.join(u) + v #2+1=3バイト

    return c

#K-PKE復号化
def k_pke_dec(dk_PKE: list[int], c: bytes) -> bytes:
    #入力：秘密鍵(dk_PKE),暗号文(c)
    #出力：復号文(m')

    #1.暗号文のデコード
    u_byte = c[0:2]
    v = c[2:]

    #2.UとVを復元
    # バイト列から係数リストに直し、（0,q-1）表現の係数リストを復元
    U = [poly_utils.Decompress(i, 1) for i in poly_utils.ByteDecode(u_byte, 1, k)]
    V = [poly_utils.Decompress(i, 1) for i in poly_utils.ByteDecode(u_byte, 1, 1)]

    #3.秘密鍵を復元
    # バイト列から（0,q-1）表現の係数リストを復元
    s = poly_utils.ByteDecode(dk_PKE, 5, k)

    #4.中間多項式を生成
    #w = V - s * NTT(U)
    ntt_U = [poly_utils.NTT(poly,psi) for poly in U]
    term_ntt = [0] * n
    for j in range(k):
        prod = poly_utils.poly_mul_ntt(s[j], ntt_U[j])  
        term_ntt = poly_utils.poly_add(term_ntt, prod)
    w = poly_utils.poly_sub(V[0], poly_utils.NTT_rev(term_ntt,psi_rev))
    
    #5.メッセージの復元
    #バイト列を復元
    m = poly_utils.ByteEncode(poly_utils.Compress(w,1), 1)

    return m









