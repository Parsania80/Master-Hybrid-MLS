// INPUTS:
// pk_x25519 (From the node's position in Tree A)
// pk_kyber768 (From the node's position in Tree B)
// path_secret: The single 32-byte secret being passed up both trees

function Parallel_Trees_Encapsulate(pk_x25519, pk_kyber768, path_secret):
    
    // ==========================================
    // TREE A OPERATION (Pure Classical HPKE)
    // ==========================================
    (enc_x, ss_x) <- KEM_X25519.Encaps(pk_x25519)                    // enc_x is 32 bytes
    
    key_env_x <- KDF.Expand(ss_x, "hpke_key", 32)
    nonce_x   <- KDF.Expand(ss_x, "hpke_nonce", 12)
    
    // AEAD Encrypt for Tree A (32 byte secret + 16 byte MAC tag = 48 bytes)
    ciphertext_A <- AEAD.Encrypt(key_env_x, nonce_x, plaintext = path_secret)
    
    // ==========================================
    // TREE B OPERATION (Pure Post-Quantum HPKE)
    // ==========================================
    (enc_k, ss_k) <- KEM_Kyber768.Encaps(pk_kyber768)                // enc_k is 1088 bytes
    
    key_env_k <- KDF.Expand(ss_k, "hpke_key", 32)
    nonce_k   <- KDF.Expand(ss_k, "hpke_nonce", 12)
    
    // AEAD Encrypt for Tree B (32 byte secret + 16 byte MAC tag = 48 bytes)
    ciphertext_B <- AEAD.Encrypt(key_env_k, nonce_k, plaintext = path_secret)
    
    // ==========================================
    // Final Output Package Assembly
    // ==========================================
    return {
        Tree_A_Payload: {
            kem_output: enc_x,            // 32 bytes
            ciphertext: ciphertext_A      // 48 bytes
        },
        Tree_B_Payload: {
            kem_output: enc_k,            // 1088 bytes
            ciphertext: ciphertext_B      // 48 bytes
        }
    }                                     // TOTAL: 1216 bytes
