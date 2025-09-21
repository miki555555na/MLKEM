#ML-KEM実装
#n=8 q=17 k=2 の実装例(簡略版)
from ..utils import hash_utils
from ..kpke import kpke_core

#パラメータ
n = 8 #多項式の次数
q = 17 #係数の法
k = 2 #多項式の数 (k=eta) 
psi = pow(3, (q-1) // n, q) #n次の原始根

#ML-KEM鍵生成
def mlkem_keygen(seed1: bytes,seed2: bytes):
    #入力：32バイトの乱数 d,z
    #出力：鍵カプセル化鍵（ek),鍵デカプセル化鍵(dk)
    (ek_PKE, dk_PKE) = kpke_core.k_pke_keygen(seed1)
    ek = ek_PKE
    dk = dk_PKE + ek + hash_utils.hash_H(ek) + seed2
    return(ek,dk)

#ML-KEMカプセル化
def mlkem_encaps(ek: bytes, m: bytes):
    #入力：鍵カプセル化鍵（ek)、乱数メッセージ（m）
    #出力；共通鍵（k_enc）,暗号文（c）

    #1.セッション鍵シード生成
    k_seed = m + hash_utils.hash_H(ek)

    #2.共通鍵と乱数生成
    (K, r) = hash_utils.hash_G(k_seed, 1) 

    #3.K-PKE暗号化
    c = kpke_core.k_pke_enc(ek, m, r)

    return(K, c)

#ML-KEMデカプセル化
def mlkem_decaps(dk: bytes, c: bytes):
    #入力：デカプセル化鍵（dk）、暗号文（c_dec）
    #出力：共通鍵（K_dec）

    #1デカプセル化鍵を分解
    dk_PKE = dk[0 : 10]           #10バイト
    ek_PKE = dk[10 : 52]          #10 + 32 = 42バイト
    hashed_ek = dk[52 : 52 + 32]  #ハッシュ関数Hの出力は32バイト
    z = dk[84 : 84 + 32]          #乱数zは32バイト

    #2.暗号文の復元
    m_dec = kpke_core.k_pke_dec(dk_PKE, c) #暗号文を復元し、乱数メッセージを得る

    """
    ML-KEMデカプセル化では、受け取った暗号文を復号して得た情報をもとに、もう一度ゼロから暗号文を再計算
    再計算した暗号文と、受け取った暗号文が完全に一致するかを検証
    <= 一致しなかった場合は、偽の共通鍵を返すことでCCA安全性を保証する
    """

    #3.共通鍵と乱数の生成
    (K_dec, r_dec) = hash_utils.hash_G(m_dec + hashed_ek, 1)

    #4.偽の共通鍵の生成
    fake_K = hash_utils.hash_J(z + c, 32)

    #5.暗号文の再暗号化
    c_dec = kpke_core.k_pke_enc(ek_PKE, m_dec, r_dec)
    if(c != c_dec):
        K_dec = fake_K
    
    return K_dec









