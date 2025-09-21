#K-PKE実装
#n=8 q=17 k=2 の実装例(簡略版)
from . import hash_utils
import math

#パラメータ
n = 8 #多項式の次数
q = 17 #係数の法
k = 2 #多項式の数 (k=eta)

#=====エンコード・デコード=====

def ByteEncode(F: list[int], d: int):
    #役割：(0,q-1)範囲の整数リストの各要素をdビット表現にした(n x d ビット)後、バイト化する。
    b = [0] * (n * d)
    for i in range(n):
        a = F[i] 
        for j in range(d):
            b[i * d + j] = a & 1
            a >>= 1
    return hash_utils.BitsToBytes(b)

def ByteDecode(B: bytes, d: int, k: int) -> list[list[int]]:
    #役割：エンコードでバイト化されたものを整数リスト(k個)に戻す。
    bit_list = hash_utils.BytesToBits(B)
    polynomials = []
    for poly_idx in range(k):
        poly = []
        for coeff_idx in range(n):
            coeff = 0
            for bit_idx in range(d):
                bit_position = poly_idx * n * d + coeff_idx * d + bit_idx
                coeff |= (bit_list[bit_position] << bit_idx)
            coeff %= q  # mod q
            poly.append(coeff)
        polynomials.append(poly)
    return polynomials

#=====乱数分布=====

def sample_poly_cbd(seed: bytes, eta: int):
    #役割：乱数バイト列から中心二項分布に従う多項式の係数をサンプリングし、n次元多項式のリストを生成する
    b = hash_utils.BytesToBits(seed)
    coefficients = [0] * n
    for i in range(n):
        x = 0
        y = 0
        for j in range(eta):
            x += b[2 * i * eta + j]
            y += b[2 * i * eta + j + eta]
        coefficients[i] = (x - y) % q
    return coefficients

#=====圧縮・復元=====
#q+1/2 <= 4 =>0
#q+1/2 >= 5 =>1
def Compress(vec: list[int], d: int) -> list[int]:
    #役割：{0,q-1}の範囲のリストを{0,1}の範囲に変換する
    n = len(vec)
    result = [0] * n
    for i in range(n):
        if(((vec[i] + 1) // 2) >= 5):
            result[i] = 1
        else:
            result[i] = 0
    return result

def Decompress(vec: list[int], d: int) -> list[int]:
    #役割：{0,1}範囲のリストをqの範囲に変換する
    n = len(vec)
    result = [0] * n
    for i in range(n):
        if (vec[i] == 0):
            result[i] = 0
        else:
            result[i] = (q + 1) // 2
    return result

#=====多項式演算=====
def poly_add(poly1: list[int], poly2: list[int]) -> list[int]:
    # zipで2つのリストの要素を同時に取り出し、計算結果を新しいリストとして返す
    return [(p1 + p2 + q) % q for p1, p2 in zip(poly1, poly2)]

def poly_mul_ntt(poly1: list[int], poly2: list[int]) -> list[int]:

    return [(p1 * p2 + q) % q for p1, p2 in zip(poly1, poly2)]

def poly_sub(poly1: list[int], poly2: list[int]) -> list[int]:

    return [(p1 - p2 + q) % q for p1, p2 in zip(poly1, poly2)]

#=====NTT関連=====

def sample_ntt(input_data: bytes) -> list[int]:
    #役割：NTT多項式の係数リストを生成する
    ctx = hash_utils.XOF()
    ctx.absorb(input_data) #乱数ストリームを生成
    coefficients = []
    chunk_size = 16 #乱数ストリームの出力を16バイトに設定(まとめて乱数生成することで効率性向上)
    buffer = b''
    while len(coefficients) < n:
        if len(buffer) < chunk_size:
            buffer += ctx.squeeze(chunk_size)
        b = buffer[0] #バッファから1バイト取り出す
        buffer = buffer[1:] #バッファの更新
        val = b & 0x1F  #下位5ビットの抽出
        if val < q: #qによるフィルタリング（q(=17) < 2^5 ）
            coefficients.append(val)
    return coefficients 

def NTT(poly: list[int], psi: int):
    #役割：係数リストをNTT多項式の係数リストに変換する

    f = poly.copy()
    #リストの順序を入れ替える
    for i in range(n):
        rev_i = hash_utils.bit_rev(i, int(math.log2(n)))
        if i < rev_i:
            f[i], f[rev_i] = f[rev_i], f[i] 

    # バタフライ演算
    length = 2 #ステージを表しlength 2,4,8 と計算規模を大きくする
    while length <= n:
        half_len = length // 2
        # ステージごとの回転因子
        zeta_base = pow(psi, n // length, q) 
        for start in range(0, n, length): #処理するブロックの開始位置
            zeta = 1
            for j in range(start, start + half_len): #length長のブロック
                t = (zeta * f[j + half_len]) % q
                f[j + half_len] = (f[j] - t + q) % q
                f[j] = (f[j] + t) % q
                zeta = (zeta * zeta_base) % q
        length *= 2
    return f

def NTT_rev(poly: list[int], psi_rev: int):
    # NTTとほぼ同じ構造で逆の回転因子を使う
    f_ntt = NTT(poly, psi_rev) # NTT関数を psi_rev で再利用

    # 最後に n の逆元を掛ける（NTT変換でn倍されているため）
    n_inv = pow(n, -1, q)
    return [(coeff * n_inv) % q for coeff in f_ntt]



