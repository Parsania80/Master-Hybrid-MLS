def batch_hybrid_encapsulate(classical_pks, pq_pks):
    # 1. Classical Batching (e.g., X25519)
    # Generate one ephemeral key pair
    eph_priv, eph_pub = generate_x25519_keypair()
    
    # 2. PQ Batching (ML-KEM)
    # Generate shared lattice randomness 'r' and compute 'u' ONCE
    r = generate_mlkem_randomness()
    u = compute_mlkem_u(matrix_A, r) 
    
    ciphertexts = []
    shared_secrets = []
    
    for i in range(len(pq_pks)):
        # Classical ECDH
        ss_classic = x25519_dh(eph_priv, classical_pks[i])
        
        # PQ Math: Only compute the 'v' component for each recipient
        v_i, ss_pq = compute_mlkem_v(pq_pks[i], r)
        
        # Combine securely
        ss_combined = hkdf_extract(b"", ss_classic + ss_pq)
        
        ciphertexts.append({
            "v_component": v_i  # We don't append 'u' here!
        })
        shared_secrets.append(ss_combined)
        
    return {
        "classical_ephemeral_pub": eph_pub, # Sent once
        "pq_u_component": u,                # Sent once
        "recipient_ciphertexts": ciphertexts # Only contains 'v'
    }, shared_secrets
