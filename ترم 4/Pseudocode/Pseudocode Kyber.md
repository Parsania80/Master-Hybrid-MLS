# kyber-flow.md
## Detailed Pseudocode for Kyber (ML-KEM)

**Notation:**
*   $A$: Public matrix of polynomials
*   $s, e$: Secret vector and error vector (small coefficients)
*   $t$: Public vector
*   $H()$, $G()$, $KDF()$: Hash functions (SHA3/SHAKE based)

---

### 1. Key Generation: $Kyber.KeyGen()$
**Purpose:** Create the public and private keys.

BEGIN KeyGen
// 1. Generate matrix A from a random seed
$\rho, \sigma \leftarrow RandomBytes(32)$
$A \leftarrow Expand(\rho)$ 

// 2. Sample secret $s$ and error $e$ from a centered binomial distribution (CBD)
$s \leftarrow SampleCBD(\sigma, 0)$
$e \leftarrow SampleCBD(\sigma, 1)$

// 3. Compute the public key vector $t$
$t \leftarrow As + e$

// 4. Format keys
$pk \leftarrow (t, \rho)$  // Public key is the vector and the seed for A
$sk \leftarrow (s, pk, H(pk), z)$ // Secret key includes s, the pk, its hash, and a random rejection seed $z$
RETURN $(pk, sk)$
END KeyGen

---

### 2. Encapsulation: $Kyber.Encaps(pk)$
**Purpose:** Generate shared secret $K$ and ciphertext $c$.

BEGIN Encaps
// 1. Generate a random 32-byte message $m$
$m \leftarrow RandomBytes(32)$

// 2. Hash message and public key to derive shared key $K$ and encryption coins $r$
$(\bar{K}, r) \leftarrow G(m || H(pk))$

// 3. Encrypt the message $m$ using the basic CPAPKE scheme
// This involves expanding A, and computing:
// $u = A^T r + e_1$ 
// $v = t^T r + e_2 + Decompress(m)$
$c \leftarrow Kyber.CPAPKE.Encrypt(pk, m, r)$

// 4. Derive final shared key $K$ using a Key Derivation Function
$K \leftarrow KDF(\bar{K} || H(c))$

RETURN $(K, c)$
END Encaps

---

### 3. Decapsulation: $Kyber.Decaps(sk, c)$
**Purpose:** Safely recover shared secret $K$.

BEGIN Decaps
// Unpack $sk = (s, pk, H(pk), z)$

// 1. Decrypt the ciphertext using basic CPAPKE to guess the message $m'$
// $m' = Compress(v - s^T u)$
$m' \leftarrow Kyber.CPAPKE.Decrypt(s, c)$

// 2. Re-derive the pre-key and coins $r'$ from the guessed message
$(\bar{K}', r') \leftarrow G(m' || H(pk))$

// 3. RE-ENCRYPT the guessed message to see if it perfectly matches the received ciphertext
$c' \leftarrow Kyber.CPAPKE.Encrypt(pk, m', r')$

// 4. Fujisaki-Okamoto Check: Did the re-encryption match?
IF $c == c'$ THEN
    // Success: No one tampered with the ciphertext
    $K \leftarrow KDF(\bar{K}' || H(c))$
ELSE
    // Failure/Tampering detected: Output a deterministic but useless "reject" key
    $K \leftarrow KDF(z || H(c))$
END IF

RETURN $K$
END Decaps
