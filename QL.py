import os, json, base64, secrets, hashlib

N, Q = 16, 65521  # vector length and modulus

def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(s.encode())

def rand_vec(n): return [secrets.randbelow(Q) for _ in range(n)]
def rand_mat(n): return [[secrets.randbelow(Q) for _ in range(n)] for __ in range(n)]

def dot(a, b): return sum(x*y for x, y in zip(a, b)) % Q
def matvec(A, v): return [dot(row, v) for row in A]
def matTvec(A, v): return [dot([A[i][j] for i in range(len(A))], v) for j in range(len(v))]

def ints_to_bytes(v): return b"".join(x.to_bytes(2, "little") for x in v)
def bytes_to_ints(b): return [int.from_bytes(b[i:i+2], "little") % Q for i in range(0, len(b), 2)]


# ===== Lattice Key Encapsulation=====
def keypair():
    A, s = rand_mat(N), rand_vec(N)
    b = matvec(A, s)  # b = A*s
    return {"A": A, "b": b}, {"s": s}

def encapsulate(pk):
    r = rand_vec(N)
    u = matTvec(pk["A"], r)      # capsule vector
    v = dot(pk["b"], r)          # shared scalar
    return u, v

def decapsulate(sk, u): return dot(u, sk["s"])  # recover v


# ===== Symmetric Encryption (SHA-256-based stream) =====
def key_from_v(v): return hashlib.sha256((v % Q).to_bytes(2, "little")).digest()

def keystream(key, n):
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + ctr.to_bytes(2, "little")).digest()
        ctr += 1
    return out[:n]

def xor_bytes(a, b): return bytes(x ^ y for x, y in zip(a, b))


# ===== High-Level Encrypt / Decrypt =====
def encrypt_bytes(data: bytes):
    pk, sk = keypair()
    u, v = encapsulate(pk)
    key = key_from_v(v)
    cipher = xor_bytes(data, keystream(key, len(data)))

    key_obj = {
        "s": b64e(ints_to_bytes(sk["s"])),
        "u": b64e(ints_to_bytes(u))
    }
    return b64e(cipher), b64e(json.dumps(key_obj).encode())

def decrypt_bytes(c_b64, key_b64):
    c = b64d(c_b64)
    k = json.loads(b64d(key_b64).decode())
    s, u = bytes_to_ints(b64d(k["s"])), bytes_to_ints(b64d(k["u"]))
    key = key_from_v(decapsulate({"s": s}, u))
    return xor_bytes(c, keystream(key, len(c)))


# ===== Wrappers for Text / File =====
def encrypt_text(msg): return encrypt_bytes(msg.encode())
def decrypt_text(c, k): return decrypt_bytes(c, k).decode()

def encrypt_file(p):
    with open(p, "rb") as f: data = f.read()
    return encrypt_bytes(data)

def decrypt_file(c, k, out):
    with open(out, "wb") as f: f.write(decrypt_bytes(c, k))


# ===== User Menu =====
def main():
    print("=== Toy Lattice-Based Post-Quantum Cipher ===")
    print("1. Encrypt\n2. Decrypt")
    mode = input("Choose mode: ").strip()

    print("\n1. Text message\n2. File (.txt, .pdf, .bit, etc.)")
    dtype = input("Choose data type: ").strip()

    if mode == "1":  # ENCRYPT
        if dtype == "1":
            msg = input("\nEnter message: ")
            c, k = encrypt_text(msg)
            print("\nCiphertext:\n", c, "\n\nKey:\n", k)
        else:
            p = input("\nEnter file path: ").strip()
            if not os.path.exists(p): return print("❌ File not found")
            c, k = encrypt_file(p)
            print("\nCiphertext:\n", c, "\n\nKey:\n", k)

    elif mode == "2":  # DECRYPT
        c = input("\nEnter ciphertext (Base64): ").strip()
        k = input("Enter key (Base64 JSON): ").strip()
        if dtype == "1":
            print("\nDecrypted message:\n", decrypt_text(c, k))
        else:
            out = input("Enter output filename: ").strip()
            decrypt_file(c, k, out)
            print(f"\nDecrypted file saved as: {out}")
    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()

