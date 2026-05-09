BEGIN ProcessUpdatePath
INPUT: UpdatePath P, MyLeafIndex i, CommitterIndex c
INIT: AncestorDepth = FindCommonAncestor(i, c)

// 1. Locate the correct node in the UpdatePath
TargetNode = P.nodes[AncestorDepth]

// 2. Decrypt the path_secret for this level
// This uses HPKE to decrypt one of the ciphertexts in TargetNode.encrypted_path_secret
DecryptedPathSecret = HPKE_Decrypt(TargetNode.encrypted_path_secret, MyPrivateKey)

// 3. Hash up to the Root
CurrentSecret = DecryptedPathSecret
FOR d FROM AncestorDepth + 1 TO TreeHeight:
    CurrentSecret = KDF_Hash(CurrentSecret)
    // Derive node keys if necessary for future use
    NodeKeyPair[d] = DeriveKeyPair(CurrentSecret)

// 4. The final value is the Commit Secret
CommitSecret = CurrentSecret
RETURN CommitSecret
END ProcessUpdatePath
