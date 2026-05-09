## The Scale Problem & Group E2EE
**Concept:** Why traditional pairwise encryption fails for large groups.
**Why it is important:** Pairwise encryption requires $O(N)$ encryptions per message/key-update, destroying bandwidth and CPU for large groups.
**How it connects:** MLS introduces TreeKEM, a binary tree structure where nodes represent shared asymmetric key pairs. Updating a key requires encrypting to the public keys of the co-path, reducing the mathematical cost to $O(\log N)$. Parent nodes are not routing servers; they are shared cryptographic state.
## TreeKEM Updates (The Co-Path Action)
**Concept:** How a user updates the tree.
**The Process:** 
1. The user generates a new path secret.
2. They derive new public/private key pairs for their Direct Path (up to the Root).
3. They **encrypt** the new secrets using the **Public Keys** of the nodes on their **Co-Path**.
**Crucial Rule:** Private keys are NEVER sent over the network. Secrets are encrypted; authorized members use their existing private keys to decrypt the new secrets.
## The Scope of Post-Compromise Security (PCS)
**Concept:** Who gets healed during an update?
**The Rule:** A standard key update only heals the group if the *compromised member* is the one who performs the update. 
**Why:** If an uncompromised member updates, they encrypt the new secrets to the existing Co-Path public keys. The attacker, holding a stolen key on that Co-Path, can simply decrypt the new secrets and stay in sync.

## PublicMessage vs PrivateMessage

**KeyPackage:** A user’s pre-published cryptographic profile (HPKE public key, signature key, etc.) fetched to encrypt their Welcome message.
**Commit Message:** Sent to existing group members containing a ProposalList (e.g., adding a user) and an UpdatePath to evolve the group’s state to the next epoch.
**Welcome Message:** Sent only to the new member, containing the encrypted secrets needed to build their initial group tree.

### Topic: Adding Members (KeyPackage, Commit, Welcome)
- **The Core Problem:** New members lack the prior epoch's state ($init\_secret_{n-1}$). Therefore, they cannot process standard group updates.
- **KeyPackage:** A user's pre-published cryptographic profile (HPKE public key, signature key). Used by the adder to encrypt the onboarding secrets.
- **Commit Message:** Sent to *existing* members. Contains an `UpdatePath` to evolve the group's tree and state. Existing members use their $init\_secret_{n-1}$ combined with the new $commit\_secret$ to derive the new epoch keys.
- **Welcome Message:** Sent *only* to the new member. It contains the $joiner\_secret$ (encrypted via the KeyPackage) and the `GroupContext`. This allows the new member to bypass the need for prior state, decrypt the current tree info, and sync with the group.


### Topic: Removing Members, Proposals, and Commits
- **Proposals vs. Commits:** A `Proposal` (e.g., Remove, Add, Update) is just an intent sent to the Delivery Service. It does *not* alter the group state. A `Commit` batches one or more valid proposals and applies them, updating the tree and advancing the Epoch.
- **The Eviction Process:**
  1. A member creates a Commit containing a Remove Proposal for the target.
  2. The target's leaf and their direct path to the root are "blanked" (deleted).
  3. The committer *must* perform an `UpdatePath` to maintain Post-Compromise Security (PCS).
  4. The committer generates a new symmetric `path_secret`, which generates new **Asymmetric key pairs** for their path to the root.
  5. The target cannot decrypt the new path secrets, so they cannot compute the new `commit_secret` and are stranded in the old Epoch.


## Transcript Hashes & Authentication (RFC 9420)
**Concept:** The cryptographic chain that ensures all group members have the exact same history of Commits, preventing Delivery Services from reordering or dropping messages.
**Why it's important:** It provides cryptographic guarantee of state synchronization. If a server drops a commit, the next commit will fail to authenticate because the underlying hash chains diverge.
**The Math Chain:**
1. $confirmed\_transcript\_hash = Hash(interim\_transcript\_hash\_old \parallel CommitContent)$
2. $confirmation\_tag = MAC(confirmation\_key, confirmed\_transcript\_hash)$
3. $interim\_transcript\_hash\_new = Hash(confirmed\_transcript\_hash \parallel confirmation\_tag)$
