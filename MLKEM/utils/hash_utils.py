#ハッシュ、乱数生成
#n=8 q=17 k=2 の実装例(簡略版)
import hashlib

#パラメータ
n = 8 #多項式の次数
q = 17 #係数の法
k = 2 #多項式の数 (k=eta) 

#=====ハッシュ関数=====

def hash_G(data: bytes, k: int) -> tuple[bytes, bytes]:
    data = data + k.to_bytes(1, 'little')
    h = hashlib.sha3_512(data).digest()
    return h[:32], h[32:]

def hash_H(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def hash_J(data: bytes, output_length: int) -> bytes:
    return hashlib.shake_256(data).digest(output_length)

def prf(seed: bytes, eta: int, b: int) -> bytes:
    #役割：疑似ランダム関数(実際には規則性があるが、規則性がないように見える数字を作ってくれる関数)で、指定された長さの乱数を生成する
    assert len(seed) == 32
    assert eta in [2,3]
    assert 0 <= b < 256 # 1バイト

    output_len = 64 * eta #出力バイト数
    hasher = hashlib.shake_256()
    hasher.update(seed)
    hasher.update(bytes([b]))
    
    return hasher.digest(output_len)

#=====XOF(Extended-Output Function)=====

class XOF:
    #役割：任意の長さの暗号ハッシュを生成する
    def __init__(self):
        self.__hash__obj = hashlib.shake_128()

    def absorb(self, input_data: bytes):
        self.__hash__obj.update(input_data)

    def squeeze(self, output_length: int) -> bytes:
        return self.__hash__obj.digest(output_length)
    
#=====バイト・ビット=====
def BytesToBits(input_Byte: bytes) -> list[int]:
    bits = []
    for byte in input_Byte:
        for j in range(8):
            bits.append(byte & 1) #最下位ビットを取り出す
            byte //= 2 #次のビットに移動
    return bits

def BitsToBytes(input_data: list[int]) -> bytes:
    n_bits = len(input_data)
    assert n_bits % 8 == 0
    n_bytes = n_bits // 8
    output = [0] * n_bytes
    for i in range(n_bits):
        byte_index = i // 8
        bit_index = i % 8
        output[byte_index] |= (input_data[i] << bit_index)  
    return bytes(output)

def bit_rev(x: int, bits: int) -> int:
    #役割：指定されたビット幅(bits)でビットを反転する
    result = 0
    for i in range(bits):
        bit = (x >> i) & 1 #1ビットだけ抽出する
        result |= bit << (bits - 1 - i) #反転位置にセット
    return result
