BEGIN DHKEM_Encapsulate
INPUT: Recipient Public Key $pk_R$
INIT: Generate random scalar $sk_E$

// 1. Generate Ephemeral Public Key (encapsulated key)
COMPUTE $enc = sk_E \cdot G$

// 2. Compute the shared Diffie-Hellman value
COMPUTE $Z = sk_E \cdot pk_R$

// 3. Derive the symmetric secret using KDF
// Context ensures the secret is bound to these specific keys
INIT $context = enc || pk_R$
COMPUTE $shared\_secret = ExtractAndExpand(Z, context)$

RETURN ($shared\_secret, enc$)
END DHKEM_Encapsulate

----------------------------------------------------------

BEGIN DHKEM_Decapsulate
INPUT: Recipient Private Key $sk_R$, Encapsulated Key $enc$

// 1. Compute the shared Diffie-Hellman value
// Note: $sk_R \cdot enc = sk_R \cdot (sk_E \cdot G) = Z$
COMPUTE $Z = sk_R \cdot enc$

// 2. Derive the same symmetric secret
INIT $context = enc || pk_R$
COMPUTE $shared\_secret = ExtractAndExpand(Z, context)$

RETURN $shared\_secret$
END DHKEM_Decapsulate
