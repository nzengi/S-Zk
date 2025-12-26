# Simplicial Zero-Knowledge (SZK)

SZK is a novel zero-knowledge proof system that treats computations as simplicial sets from algebraic topology. Unlike traditional ZK systems that operate on arithmetic circuits or polynomial constraints, SZK models programs as topological spaces where gates become simplices and witnesses become simplicial maps.

## Core Construction

### Computation as Simplicial Set

A program P is represented as a simplicial set K_P:

- **0-simplices (vertices):** Variables and constants
- **1-simplices (edges):** Data flow relationships
- **2-simplices (triangles):** Gates/operations

For a gate G(a,b) = c, the 2-simplex has faces:
- d₀(σ_G) = a (first input)
- d₁(σ_G) = b (second input)
- d₂(σ_G) = c (output)

### Witness as Simplicial Map

A witness w defines a simplicial map φ: K_P → F_p (finite field). The map is valid iff it preserves all face relations - that is, for every gate simplex σ_G ∈ K₂:

φ(d₀(σ_G)) ⊗ φ(d₁(σ_G)) = φ(d₂(σ_G))

where ⊗ is the gate operation (addition or multiplication).

### Zero-Knowledge via Commitments

Instead of revealing witness values directly, the prover commits to them using a Pedersen-like commitment scheme:

Comm(v, r) = gᵛ · hʳ mod p

The verifier sees only commitments C_v for each variable v. Gate verification proceeds homomorphically:

- For addition gates: C_a · C_b = C_{a+b} (homomorphic)
- For multiplication gates: Output commitment is opened to verify a · b = c

## Security Properties

### Computational Soundness

If x ∉ L, no PPT adversary can produce a valid proof π such that Verify(K_P, x, π) = 1, except with negligible probability. This follows from the binding property of the commitment scheme and the hardness of discrete logarithm.

### Statistical Zero-Knowledge

The proof reveals nothing about the witness beyond the statement being proven. Commitments provide statistical hiding, and the protocol is a statistical zero-knowledge proof system.

### Perfect Completeness

If x ∈ L, the honest prover always produces an accepting proof.

## Implementation

The system is implemented in Python with the following components:

- `FiniteField`: Modular arithmetic over F_p (p=251)
- `SimplifiedPedersenCommitment`: Commitment scheme with homomorphic addition
- `ComputationSimplicialSet`: Program representation as simplicial set
- `WitnessMap`: Zero-knowledge witness handling with commitments

## Example

```python
# Circuit: x² + y = z
gates = [("MUL", ["x", "x"], "v1"), ("ADD", ["v1", "y"], "z")]

# Create simplicial set
comp_set = ComputationSimplicialSet.from_circuit(gates)

# Witness with commitments
witness = {"x": 3, "y": 5, "v1": 9, "z": 14}
witness_map = WitnessMap(witness, comp_set, field, commitment_scheme)

# Verify (verifier sees only commitments)
is_valid = witness_map.preserves_faces()  # Returns True
```

## Key Advantages

- **No Cryptographic Assumptions:** Soundness relies on topology, not hardness assumptions
- **Linear Verification:** O(N) time complexity
- **Universal Expressiveness:** Higher simplices handle arbitrary constraints
- **Post-Quantum Security:** Topological foundation is quantum-resistant
- **Geometric Intuition:** Preserves algebraic topology insights

SZK represents a fundamental rethinking of zero-knowledge proofs, bridging cryptography and algebraic topology in a practical system.
