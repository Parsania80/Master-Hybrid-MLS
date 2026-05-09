// INPUTS:
// pk_composite: Contains (pk_x25519, pk_kyber768)
// path_secret: The 32-byte secret being passed up the MLS tree

function Hybrid_HPKE_Encapsulate(pk_composite, path_secret):
    
    // 1. Classical KEM (X25519)
    // enc_x is the ephemeral public key (32 bytes)
    // ss_x is the classical shared secret (32 bytes)
    (enc_x, ss_x) <- KEM_X25519.Encaps(pk_composite.pk_x25519)
    
    // 2. Post-Quantum KEM (Kyber768)
    // enc_k is the Kyber ciphertext (1088 bytes)
    // ss_k is the PQ shared secret (32 bytes)
    (enc_k, ss_k) <- KEM_Kyber768.Encaps(pk_composite.pk_kyber768)
    
    // 3. The Hybrid Combiner (KDF Mixing)
    // We concatenate the shared secrets and feed them into a KDF (like HKDF)
    // This yields a single, quantum-resistant shared secret.
    hybrid_shared_secret <- KDF.Extract( salt="", IKM = (ss_x || ss_k) )
    
    // 4. HPKE Key Schedule
    // Derive the Key Encryption Key (KEK) and Nonce for the AEAD
    key_env <- KDF.Expand(hybrid_shared_secret, "hpke_key", 32)
    nonce   <- KDF.Expand(hybrid_shared_secret, "hpke_nonce", 12)
    
    // 5. AEAD Encryption (ChaCha20Poly1305 or AES-GCM)
    // Encrypts the 32-byte path_secret. Adds a 16-byte MAC tag.
    // Length: 32 + 16 = 48 bytes
    encrypted_payload <- AEAD.Encrypt(key_env, nonce, plaintext = path_secret)
    
    // 6. Final Output Package Assembly
    return {
        kem_output_x25519: enc_x,         // 32 bytes
        kem_output_kyber: enc_k,          // 1088 bytes
        ciphertext: encrypted_payload     // 48 bytes
    }                                     // TOTAL: 1168 bytes
