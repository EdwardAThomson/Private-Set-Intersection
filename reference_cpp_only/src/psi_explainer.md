# Private Set Intersection (PSI) Explanation page

## Private Set Intersection (PSI) Overview
Private Set Intersection (PSI) is a cryptographic technique that allows two parties to find common elements in their datasets without revealing any non-matching items. This process ensures privacy, as neither party learns anything about the other's data beyond the shared elements.

In our example, Alice and Bob are both players in a mock RTS game. Each player has a set of units, and they want to determine if they have any common unit positions without revealing the details of their armies to each other.

How It Works:
1. **Key Derivation**: Bob picks a private scalar. For each of his unit positions, he hashes the position onto the curve, multiplies by his private scalar, and derives a per-position symmetric key from the result.

2. **Membership Tags**: For every position, Bob sends a one-way *membership tag*: a hash of the derived key (BLAKE3 in derive-key mode). The tag reveals nothing about the position, and every tag is the same fixed size, so not even the length of an element leaks.

3. **Blinding and Exchange**: Alice hashes each of her positions onto the curve and blinds each one with an independent random scalar before sending them. Bob multiplies each blinded point by his private scalar and returns them. The blinding means Bob learns nothing about Alice's positions.

4. **Intersection Identification**: Alice unblinds each returned point, derives the same kind of key Bob derived, and hashes it into a tag. If her tag appears in Bob's list, that position is shared. She already knows which position it is: it is her own input at that index. Positions that are not shared produce tags that match nothing, and she can compute nothing further from them.

By the end of this protocol, both Alice and Bob only know about the unit positions they have in common, without exposing any other information.

The protocol is private against honest-but-curious participants. A malicious participant can probe membership by fabricating inputs; binding inputs to prior commitments (dispute resolution) is future work tracked in the repository roadmap.

## Protocol Details
Here is a deeper dive into the protocol details. As it is a pain to copy and paste the text from ChatGPT, it is easier to provide a screenshot:

![PSI Protocol Deatails](psi_details.png)

Note: the screenshot describes the classical formulation, in which Bob encrypts each position under its derived key and Alice trial-decrypts. This implementation uses membership tags instead (see below), which answer the same "do our keys match?" question with a single hash comparison.

## Key Concepts

### Concept of HashToGroup:
In the research paper there is a hash function, **H1**, which is somewhat different from a regular hash function.

**HashToGroup** typically means hashing an input (like a string or integer) to an element in a cryptographic group. In our case, the group is ristretto255, a prime-order group built on Curve25519.

The goal is to take some arbitrary input, like a string, and map it deterministically to a valid group element. This is useful in protocols like the one we're working on because you need inputs (like unit positions) to be represented as group elements for operations like scalar multiplication.

One property is critical: nobody may know the discrete logarithm of the mapped point. Hashing to a *scalar* and multiplying the generator (`H(x)*G`) looks similar but is broken: the discrete log is then public, and one protocol run lets a participant recover enough information to enumerate the other party's entire set offline. This implementation uses `crypto_core_ristretto255_from_hash` (an Elligator 2 based map), which produces points with unknown discrete log.

### The H2 Function in the PSI Protocol (PSI Demo):

**Purpose**
The **H2** function in the PSI protocol maps group elements to a fixed-size bit string, used here as the per-element symmetric key material from which the membership tag is derived.

**Process**
The 32-byte canonical encoding of the group element is hashed with SHA-512 and truncated to 32 bytes.

### Group Choice:

#### ristretto255

This implementation uses [ristretto255](https://ristretto.group/), a prime-order group constructed over Curve25519. It avoids the cofactor pitfalls of raw Curve25519 and the trust concerns some cryptographers raise about the NIST curves (see [SafeCurves](https://safecurves.cr.yp.to/) by Daniel J. Bernstein and Tanja Lange). Earlier versions of this project used NIST P-256; the switch to ristretto255 came with the hash-to-group fix described above.

### Membership tags instead of encryption:

The classical protocol has Bob encrypt each position under its derived key; Alice tests membership by attempting decryption, since only a matching key opens the box. That works, but the plaintext inside is redundant (Alice can only ever decrypt a value she already holds) and trial decryption costs O(A x B) attempts.

This implementation sends a **membership tag** instead: BLAKE3 in derive-key mode (context string `PSI-membership-tag-v1`) over the derived key. Alice recomputes tags for her own elements and checks membership in a hash set, which is O(A), and every wire entry is a fixed 32 bytes. Tag matching relies on collision resistance of the hash rather than the authenticity of a ciphertext; both give a negligible false-match probability.

BLAKE3 was chosen for the tag and for deterministic scalar derivation because it is fast, modern, and already part of the project. For gaming, we need speed while being secure enough.
