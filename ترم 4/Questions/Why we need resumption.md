1. Tree “Health” (Pruning Blank Nodes)
In a long-lived group with many members leaving or being removed, the Ratchet Tree can become “sparse.”

The Problem: When a member is removed, their leaf and all nodes on their direct path become blank. Over time, if many people leave, the tree becomes full of “holes” (blank nodes).
The Impact: This makes the tree less efficient for remaining members.
The Reset: Instead of sending many individual Commit messages to “unblank” the tree, the group can use Resumption to start a brand-new, perfectly balanced tree with only the current active members.
2. Changing Group Parameters (CipherSuite Migration)
In a standard MLS group, you cannot simply “change” the math in the middle of an epoch.

The Problem: If the group started using a CipherSuite that is now considered weak (e.g., a non-Quantum-Resistant one) or if they want to change the Extensions (like the maximum message size), they cannot do this within the existing GroupContext.
The Reset: To change the CipherSuite or Protocol Version, the members must create a new group. By using the resumption_psk, they ensure that only the members of the old group (using the old math) can transition to the new group (using the new math).
3. Resource Management for “Zombie” Members
This is the scenario you touched on earlier.

The Problem: If a group has 10,000 members but only 1,000 are active, the active members are constantly generating UpdatePath data for a massive tree that mostly contains “zombies” (inactive users).
The Reset: The active members can “resume” into a smaller group. This reduces the 𝑂(log⁡𝑁)
O(logN) overhead of every future Commit because  
N (the number of members) is now much smaller.
One more “Secret” reason (Section 16.7): Deniability
Sometimes, a group might want to “break” the cryptographic chain intentionally to limit the scope of what an attacker could find if they stole a phone. While MLS has Forward Secrecy, starting a new group with a Resumption PSK provides a clean “Security Boundary.”