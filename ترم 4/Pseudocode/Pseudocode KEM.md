## Algorithm / Cryptography Reference

**Name:** Generic Key Encapsulation Mechanism (KEM)
**Purpose:** To securely establish a shared symmetric key between two parties using asymmetric cryptography.
**Inputs:** Receiver's Public Key $pk$, Receiver's Secret Key $sk$
**Outputs:** Shared Symmetric Key $K$, Ciphertext $c$

**Pseudocode:**
BEGIN Generic_KEM

// Step 1: Receiver generates keys
INIT: $(pk, sk) \leftarrow KeyGen()$
// Receiver publishes $pk$

// Step 2: Sender encapsulates a new symmetric key
INIT: $(K, c) \leftarrow Encaps(pk)$
// Sender transmits $c$ to Receiver

// Step 3: Receiver decapsulates to recover the key
COMPUTE: $K' \leftarrow Decaps(sk, c)$

// If successful, $K == K'$
RETURN $K$
END Generic_KEM
