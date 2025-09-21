#ML-KEMの外部実装
#n=8 q=17 k=2 の実装例(簡略版)
from . import mlkem_core

def mlkem_keygen(seed1: bytes,seed2: bytes):
    #入力：32バイトの乱数 d,z
    #出力：鍵カプセル化鍵（ek),鍵デカプセル化鍵(dk)
    assert len(seed1) == 32
    assert len(seed2) == 32
    (ek,dk) = mlkem_core.mlkem_keygen_internal(seed1, seed2)

    return (ek,dk)

def mlkem_enc(ek: bytes, m: bytes):
    #入力：鍵カプセル化鍵（ek)、乱数メッセージ（m）
    #出力；暫定鍵（k）,暗号文（c）
    assert len(m) != None
    (K, c) = mlkem_core.mlkem_enc_internal(ek, m)
    return (K, c)

def mlkem_dec(dk: bytes, m: bytes):
    