**Q:** What is the difference between Forward Secrecy (FS) and Post-Compromise Security (PCS) in MLS?
**A:** 
- **FS** protects the *past*: A stolen key today cannot decrypt yesterday's messages.
- **PCS** protects the *future*: A stolen key today becomes useless for future messages as soon as a normal tree update (Commit) occurs.



## Adding Members to MLS
**Q:** Why can't a new member just use the `Commit` message to join the group?
**A:** Because calculating the new epoch's secrets requires the $init\_secret$ from the *previous* epoch. A new member has no prior state, so they must be explicitly handed the $joiner\_secret$ via a separate `Welcome` message.

**Q:** What is the purpose of a `KeyPackage` in MLS?
**A:** It is a pre-published bundle containing a user's public keys (e.g., HPKE public key). It allows another member to asynchronously encrypt a `Welcome` message specifically for them.

## Algorithm / Cryptography Reference

**Name:** Joiner Secret Derivation
**Purpose:** Combines the running group state with the new update secret to bridge existing members and new members.
**Inputs:** $init\_secret_{n-1}$ (State from last epoch), $commit\_secret$ (From the new UpdatePath)
**Outputs:** $joiner\_secret$ (The anchor for the new epoch's keys)

**Pseudocode:**
```text
BEGIN Joiner Secret Derivation
INPUT: init_secret_prev, commit_secret

// Core Logic
// If there is no previous state (e.g., group creation), init_secret_prev is a zero-string.
COMPUTE joiner_extract = HKDF_Extract(init_secret_prev, commit_secret)

RETURN joiner_extract
END Joiner Secret Derivation
```

## Removing Members & Commits
**Q:** What is the difference between a Proposal and a Commit in MLS?
**A:** A Proposal is a public declaration of intent (like asking to remove a member) that does not change the tree. A Commit is the action that batches proposals, applies the changes to the Ratchet Tree, updates the cryptographic state, and advances the Epoch.

**Q:** When creating a Commit to remove a member, what cryptographic action must the committer take on their own leaf?
**A:** They must perform a path update (`UpdatePath`). They generate a new `path_secret` to derive new Asymmetric keys up to the root, ensuring the removed member has no knowledge of the new shared secrets (Post-Compromise Security).
