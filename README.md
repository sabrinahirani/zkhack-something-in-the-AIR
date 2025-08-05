## zkHack Challenge #7: Something in the AIR

*Challenge: [https://www.zkhack.dev/events/puzzle7.html](https://www.zkhack.dev/events/puzzle7.html)*

---

### Relevant Background

#### STARKs

There is a well-known impossibility result that non-interactive zero-knowledge proofs (NIZKs) with computational soundness require some form of CRS. STARKs avoid this by using a **random oracle model**, replacing the CRS with hash-based commitments (typically Merkle trees).

Although STARKs and SNARKs both encode computations into polynomials, the commitments differ:

* **SNARKs**: Use *algebraic* (e.g., KZG) commitments
* **STARKs**: Use *hash-based* (Merkle) commitments

This design makes STARKs fully transparent and post-quantum secure.

---

**AIR: Algebraic Intermediate Representation**

Unlike SNARKs (which encode computation as circuits using R1CS or QAPs), STARKs represent computation as state transitions over time.

An execution trace is a table:

* Rows: Steps of computation (time)
* Columns: Registers (memory/state)
* Constraints: Relations between rows and columns

This design maps naturally to Merkle trees (each column is a vector → committed).

#### Example: Fibonacci Trace

```
Step | x | y
-----|---|---
  0  | 1 | 1
  1  | 1 | 2
  2  | 2 | 3
  3  | 3 | 5
```

Here, the transition constraints are:

* $f_x(\omega x) = f_y(x)$
* $f_y(\omega x) = f_x(x) + f_y(x)$

Boundary constraints might be:

* $f_x(x_0) = 1$
* $f_y(x_0) = 1$

The full system is enforced by a constraint polynomial $C(x)$, which must evaluate to zero over the domain.

> AIR enables direct encoding of sequential computation and is especially suited for STARKs, which require traces to be explicitly encoded and committed.

---

### Merkle-Based Polynomial Commitments

In STARKs, a prover commits to a polynomial $f(x)$ by evaluating it on a domain $D$, then building a Merkle tree over the evaluations:

* Leaves: Hashes of $f(x_i)$ for $x_i \in D$
* Merkle root: The commitment
* Openings: Merkle proofs + queried values

However, Merkle trees only prove inclusion of values — not structur*. So we must verify that the committed evaluations come from a low-degree polynomial.

---

### Low-Degree Testing via FRI

To prove the committed evaluations form a low-degree polynomial, STARKs use FRI (Fast Reed-Solomon Interactive Oracle Proof of Proximity):

* Recursively fold polynomials using affine combinations
* At each round, commit to folded values using Merkle trees
* Final step reduces to checking constancy
* If $f$ is far from low-degree, inconsistency appears with high probability

This is a similar approach to the sumcheck protocol!
FRI justifies using Merkle trees for polynomial commitments and ensures soundness.

---

### Rescue Hash Function

**Rescue** is a hash function optimized for SNARKs and STARKs:

* Algebraic sponge construction
* Efficient inside arithmetic circuits and AIR
* Used in Merkle trees, nullifiers, commitments, etc.

Rescue alternates:

1. **S-boxes**: Apply power map (e.g., cube or inverse cube)
2. **Linear mixing**: Multiply by MDS matrix
3. **Add round constants**

Its algebraic simplicity makes it ideal for ZK protocols.

---

### The Something in the AIR Protcol 

Alice implemented a STARK-based Semaphore protocol to collect anonymous votes. She gathered public keys from 7 friends, plus her own, and built an access set.

Later, she noticed 9 valid signals for a single topic — more than the expected 8! Someone was able to submit multiple signals with different nullifiers, violating the one-vote rule.

Your task: Create a valid signal with a different nullifier on the same topic.

---

**Repository Walkthrough**

#### 1. **Semaphore Protocol**

* Proves group membership and broadcasts messages anonymously
* Uses STARKs for privacy and correctness
* Enforces:

  * Public key membership (via Merkle proof)
  * One signal per topic (via nullifiers)

#### 2. **Nullifiers**

A **nullifier** prevents double-signaling on the same topic.

It’s computed as:

```rust
nullifier = hash(private_key, hash(topic))
```

Properties:

* **Deterministic**: Same input → same nullifier
* **Unique**: Different inputs → different nullifiers
* **Binding**: Can’t compute without private key
* **Non-reusable**: Reuse = rejection

#### 3. **Technical Overview**

* Field: Prime field $F = 2^{64} - 2^{32} + 1$
* Hash: Rescue Prime (`Rp64_256`), 7 rounds, 12-element state
* Trace:

  * 25 columns
  * 8-step hash cycles

#### 4. **Trace Layout**

```
Cols 0–3:     Merkle capacity
Cols 4–7:     Merkle hash state
Cols 8–11:    Merkle accumulated hash
Cols 12–15:   Nullifier capacity
Cols 16–19:   Nullifier hash state
Cols 20–23:   Topic hash
Col 24:       Merkle index bits
```

#### 5. **AIR / STARK System**

* `AccessSet`: Builds Merkle tree of public keys
* `SemaphoreAir`: Defines transition and boundary constraints
* `SemaphoreProver`: Generates execution trace and STARK proof

---

## Vulnerabilities

The AIR constraints contain **critical bugs** that break the protocol.

---

### Vulnerability 1: Missing Nullifier Initialization Check

The constraints **fail to check** the initial state of the nullifier hash.

```rust
// No check for nullifier state starting with capacity = 8
state[12] = Felt::new(9); // Bypasses constraint
```

➡️ **Impact**: Attacker can change the number of hash rounds, generating a different nullifier for the same topic.

---

### Vulnerability 2: Constraint Index Collision

```rust
result.agg_constraint(4, hash_init_flag, is_zero(next[3]));
result.agg_constraint(4, hash_init_flag, not_bit * are_equal(current[4], next[4]));
```

➡️ **Impact**: Two constraints with the same index `4` conflict — the second one silently overwrites the first. This weakens correctness.

---

### Vulnerability 3: Nullifier Forgery Without Private Key

The most severe: you can **fake a private key** and generate a valid nullifier.

Why?

* AIR constraints don’t check that the nullifier state was derived from `hash(priv_key, topic)`
* So an attacker can choose a nullifier, **invert Rescue**, and extract a fake preimage
* This preimage acts as a fake private key and passes verification

➡️ **Impact**: Full forgery. Can signal on behalf of *any* public key without knowing its secret key.

---

## Fix Recommendations

* Explicitly **check initial state** of every Rescue permutation (Merkle + nullifier)
* Avoid **constraint index reuse** — each constraint must be uniquely indexed
* Ensure nullifier computation is **tied to the actual private key hash**

---

Let me know if you'd like this turned into a PDF, blog post, or even a slide deck.
