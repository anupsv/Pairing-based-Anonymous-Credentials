# Re-randomizable Anonymous Credentials

This is a Rust implementation of the Re-randomizable Credentials scheme as described in the blog post [Re-randomizable Credentials for Anonymous Authentication in Decentralized Systems](https://decentralizedthoughts.github.io/2023-01-08-re-rand-cred/).

## Overview

This library provides a privacy-preserving credential system with the following key features:

1. **Attribute-based Credentials**: Users can receive credentials containing multiple attributes (like age, membership level, etc.)
2. **Re-randomizable Presentations**: The same credential can be presented multiple times without being linkable
3. **Cryptographic Verification**: Verifiers can check credential validity without learning who issued it
4. **Zero-knowledge**: Attributes remain hidden, only their validity is verified

The system is built on pairing-based cryptography using BLS12-381 curves from the Arkworks library stack.

## Core Cryptographic Building Blocks

1. **Dual Pedersen Commitments**:
   - Commitments in both G1 and G2 groups: (cm = g^r · ∏ᵢ hᵢ^mᵢ, cm̃ = g̃^r · ∏ᵢ h̃ᵢ^mᵢ)
   - The attribute generators hᵢ, h̃ᵢ are related to the issuer's secret key (hᵢ = g^yᵢ, h̃ᵢ = g̃^yᵢ)
   - This relationship is crucial for signature verification

2. **Pointcheval-Sanders Signatures**:
   - Issuer holds secret key (x, y⃗) and publishes verification key (X̃ = g̃ˣ, Ỹ)
   - Signature consists of (σ₁ = g^u, σ₂ = (g^x · cm)^u)
   - Verification uses the pairing equation: e(σ₁, X̃ · cm̃) = e(σ₂, g̃)

3. **Re-randomization Technique**:
   - Choose random r' and u'
   - Update commitment: cm' = cm · g^r', cm̃' = cm̃ · g̃^r'
   - Update signature: σ₁' = (σ₁)^u', σ₂' = (σ₂ · (σ₁)^r')^u'
   - The verification equation still holds after re-randomization

## Usage Example

```rust
// Setup phase
let domain_params = setup();

// Issuer setup
let num_attributes = 2;
let issuer_keys = keygen(&domain_params, num_attributes);
let (issuer_sk, issuer_pk) = (issuer_keys.0.clone(), issuer_keys.1.clone());

// User attributes
let mut rng = StdRng::from_rng(thread_rng()).unwrap();
let attr1 = Fr::rand(&mut rng);  // First attribute
let attr2 = Fr::rand(&mut rng);  // Second attribute
let attributes = vec![attr1, attr2];
let randomness = Fr::rand(&mut rng);

// Create commitment to attributes
let commitment = dual_commit(&domain_params, &issuer_keys, &attributes, &randomness);

// Issue credential
let credential = issue(&domain_params, &issuer_sk, &commitment);

// Verify original credential
verify(&domain_params, &issuer_pk, &credential)?;

// Re-randomize for unlinkability
let rerandomized_cred = rerand(&domain_params, &credential);

// Verify re-randomized credential (still valid!)
verify(&domain_params, &issuer_pk, &rerandomized_cred)?;
```

## Verification and Pairing Equation

The security of the scheme relies on the verification equation:

e(σ₁, X̃ · cm̃) = e(σ₂, g̃)

This holds because:
- For original credential: e(g^u, g̃^x · cm̃) = e((g^x · cm)^u, g̃)
- Bilinearity: e(g^a, g̃^b) = e(g, g̃)^(a·b)
- This equality is preserved through re-randomization

## Building and Running

```bash
# Build the library
cargo build

# Run the example
cargo run

# Run tests
cargo test
```

## Security Notes

> **WARNING**: This code is NOT audited, has NOT undergone security review, and should NOT be used in production environments. This implementation is meant strictly for educational purposes only.

- This implementation uses BLS12-381 elliptic curve pairings via the Arkworks library
- The commitment generators are derived from the issuer's secret key, ensuring the right relationship for verification
- The implementation follows the mathematical structure described in the blog post
- Many security considerations beyond basic correctness have not been addressed, including:
  - Side-channel protections
  - Secure key management

## License

MIT License