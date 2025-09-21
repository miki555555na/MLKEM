import os

from MLKEM.utils import poly_utils as pol
from MLKEM.kpke import kpke_core as pke
from MLKEM.mlkem import mlkem_core as mlkem

n = 8 #多項式の次数
q = 17 #係数の法
k = 2 #多項式の数 (k=eta)
eta = k
psi = pow(3, (q-1) // n, q) #n次の原始根
psi_rev = pow(psi, -1, q) #(ζ^-1)


def run_mlkem_test():
    """
    ML-KEMの鍵生成、カプセル化、デカプセル化のサイクルをテストします。
    """
    print("ML-KEM Simplified Test (n=8, q=17, k=2)")
    print("="*50)

    # --- 1. 鍵生成 (Key Generation) ---
    print("\n--- 1. 鍵生成中... ---")
    # 32バイトの乱数シードを2つ生成 (dとz用)
    d_seed = os.urandom(32)
    z_seed = os.urandom(32)
    ek, dk = mlkem.mlkem_keygen(d_seed, z_seed)
    print(f"✅ 公開鍵 (ek) 生成完了 (長さ: {len(ek)} bytes)")
    print(f"✅ 秘密鍵 (dk) 生成完了 (長さ: {len(dk)} bytes)")

    # --- 2. カプセル化 (Encapsulation) ---
    print("\n--- 2. カプセル化中... ---")
    # 32バイトのランダムなメッセージシードmを生成
    m_seed = os.urandom(32)
    print(f"クライアント側で生成した秘密の値 (m): {m_seed.hex()}")

    K_encaps, c = mlkem.mlkem_encaps(ek, m_seed)
    print(f"✅ 共通鍵と暗号文の生成完了")
    print(f"生成された共通鍵 (K): {K_encaps.hex()}")
    print(f"生成された暗号文 (c): {c.hex()}")

    # --- 3. デカプセル化 (Decapsulation) ---
    print("\n--- 3. デカプセル化中... ---")
    K_decaps = mlkem.mlkem_decaps(dk, c)
    print(f"✅ 共通鍵の復元完了")
    print(f"復元された共通鍵 (K_dec): {K_decaps.hex()}")

    # --- 4. 検証 (Verification) ---
    print("\n--- 4. 検証結果 ---")
    if K_encaps == K_decaps:
        print("🥳 \033[92m成功！\033[0m 生成された共通鍵と復元された共通鍵は一致します。")
    else:
        print("❌ \033[91m失敗！\033[0m 共通鍵が一致しませんでした。")
    
    print("="*50)


if __name__ == "__main__":
    run_mlkem_test()