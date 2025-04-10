/// Re-randomizable Anonymous Credentials
/// 
/// This implementation is based on the BLS12-381 elliptic curve pairing
/// using the arkworks library stack.

use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::{
    pairing::Pairing,
    Group,
};
use ark_std::{
    rand::SeedableRng,
    UniformRand,
};
use rand::thread_rng;
use rand::rngs::StdRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid parameters")]
    InvalidParameters,
}

type Result<T> = std::result::Result<T, CredentialError>;

/// Domain parameters for the credential system
///
/// The scheme uses bilinear groups (G, G̃, GT)
/// with generators g ∈ G and g̃ ∈ G̃, and a bilinear pairing e: G × G̃ → GT.
/// In our implementation, G = G1 and G̃ = G2 from the BLS12-381 curve.
#[derive(Clone, Debug)]
pub struct DomainParams {
    g: G1Projective,        // Generator of G1 (corresponds to g)
    g_tilde: G2Projective,  // Generator of G2 (corresponds to g̃)
}

impl Default for DomainParams {
    fn default() -> Self {
        Self {
            g: G1Projective::generator(),
            g_tilde: G2Projective::generator(),
        }
    }
}

/// Issuer keys for the credential system
///
/// It defines the issuer's secret key as (x, y⃗) where:
/// - x is the master secret key
/// - y⃗ = (y₁, y₂, ..., yₗ) are attribute-specific secrets
///
/// Additionally, we store the attribute generators h_i = g^y_i for commitment
/// creation, which ensures the correct relationship for signature verification.
#[derive(Clone, Debug)]
pub struct IssuerSecretKey {
    x: Fr,                     // Master secret (x in the blog)
    y: Vec<Fr>,                // Per-attribute secrets (y vector in the blog)
    h: Vec<G1Projective>,      // Attribute generators for G1 (h_i = g^y_i)
}

/// Public verification key for the credential system
///
/// This corresponds to the verification key in the Pointcheval-Sanders signature scheme
/// described in the blog post. Also includes the generators for G2.
#[derive(Clone, Debug)]
pub struct IssuerPublicKey {
    x_tilde: G2Projective,        // g_tilde^x (X̃ in the blog)
    y_tilde: Vec<G2Projective>,   // g_tilde^y_i for each attribute (Ỹ in the blog)
    h_tilde: Vec<G2Projective>,   // Attribute generators for G2 (h_tilde_i = g_tilde^y_i)
}

/// Dual Pedersen commitment
///
/// From the blog post: "We use a dual Pedersen commitment scheme that generates a
/// commitment in both G and G̃". This helps us create credentials that can be re-randomized.
///
/// The commitment is computed as:
/// - cm = g^r · ∏ᵢ₌₁ᵏ hᵢ^mᵢ in G
/// - cm̃ = g̃^r · ∏ᵢ₌₁ᵏ h̃ᵢ^mᵢ in G̃
/// 
/// where r is a random value, mᵢ are the attributes, and hᵢ, h̃ᵢ are attribute-specific generators.
#[derive(Clone, Debug)]
pub struct DualCommitment {
    cm: G1Projective,       // Commitment in G1 (cm in the blog)
    cm_tilde: G2Projective, // Commitment in G2 (cm̃ in the blog)
}

/// Re-randomizable signature
///
/// This implements the Pointcheval-Sanders signature scheme described in the blog.
/// The signature consists of two elements (σ₁, σ₂) where:
/// - σ₁ = g^u
/// - σ₂ = (g^x · cm)^u
///
/// where u is a random scalar used for signing.
#[derive(Clone, Debug)]
pub struct Signature {
    pub sigma1: G1Projective,   // g^u (σ₁ in the blog)
    pub sigma2: G1Projective,   // (g^x · cm)^u (σ₂ in the blog)
}

/// Credential containing a commitment and signature
///
/// A credential in this system consists of a dual commitment to the attributes
/// and a Pointcheval-Sanders signature on that commitment. This structure allows
/// for re-randomization while maintaining verifiability.
#[derive(Clone, Debug)]
pub struct Credential {
    pub commitment: DualCommitment,
    pub signature: Signature,
}

/// Setup function: Generate domain parameters
///
/// This corresponds to the Setup algorithm that establishes
/// the bilinear groups and generators needed for the credential system.
pub fn setup() -> DomainParams {
    DomainParams::default()
}

/// Generate issuer keys for a given number of attributes
///
/// This implements the KeyGen algorithm which creates:
/// - Secret key: (x, y⃗) where x is a master secret and y⃗ are attribute-specific secrets
/// - Public key: (X̃ = g̃ˣ, Ỹ = (g̃ʸ¹, g̃ʸ², ..., g̃ʸᵏ))
///
/// Additionally, it computes the attribute-specific generators:
/// - In G1: h_i = g^y_i for each attribute
/// - In G2: h_tilde_i = g_tilde^y_i for each attribute
///
/// These keys are used by the credential issuer to sign credentials and by verifiers
/// to check credential validity, while the generators are used for commitments.
pub fn keygen(params: &DomainParams, num_attributes: usize) -> (IssuerSecretKey, IssuerPublicKey) {
    let mut rng = StdRng::from_rng(thread_rng()).unwrap();
    
    // Generate master secret x and attribute secrets y
    let x = Fr::rand(&mut rng);
    let y: Vec<Fr> = (0..num_attributes)
        .map(|_| Fr::rand(&mut rng))
        .collect();
    
    // Compute attribute generators for G1 (h_i = g^y_i)
    let h: Vec<G1Projective> = y.iter()
        .map(|y_i| params.g * y_i)
        .collect();
    
    // Compute public verification keys and generators for G2
    let x_tilde = params.g_tilde * x;
    let y_tilde: Vec<G2Projective> = y.iter()
        .map(|y_i| params.g_tilde * y_i)
        .collect();
    
    // The h_tilde values are the same as y_tilde in this case
    let h_tilde = y_tilde.clone();
    
    (
        IssuerSecretKey { x, y, h },
        IssuerPublicKey { x_tilde, y_tilde, h_tilde }
    )
}

/// Create a dual Pedersen commitment to a set of attributes
///
/// This implements the DualCommit algorithm which creates commitments
/// in both G1 and G2 groups:
///
/// - cm = g^r · ∏ᵢ₌₁ᵏ hᵢ^mᵢ in G1
/// - cm̃ = g̃^r · ∏ᵢ₌₁ᵏ h̃ᵢ^mᵢ in G2
///
/// The key difference from standard Pedersen commitments is that our generators
/// have a specific relationship to the issuer's secret key: h_i = g^y_i and
/// h_tilde_i = g_tilde^y_i. This relationship is crucial for the signature 
/// verification to work correctly.
///
/// These dual commitments allow the signature to be re-randomized later while 
/// maintaining verifiability via the pairing equation.
pub fn dual_commit(
    params: &DomainParams,
    issuer_keys: &(IssuerSecretKey, IssuerPublicKey),
    messages: &[Fr],
    randomness: &Fr,
) -> DualCommitment {
    let (sk, pk) = issuer_keys;
    
    // If messages.len() > sk.h.len(), this would panic, so we'll ensure we
    // have the right number of attributes
    if messages.len() > sk.h.len() {
        panic!("Too many attributes for this issuer key");
    }
    
    let mut cm = params.g * randomness;
    let mut cm_tilde = params.g_tilde * randomness;
    
    // Add each message to the commitment, using the attribute generators
    // from the issuer keys
    for (i, m) in messages.iter().enumerate() {
        cm += sk.h[i] * m;
        cm_tilde += pk.h_tilde[i] * m;
    }
    
    DualCommitment { cm, cm_tilde }
}

/// Issue a credential for committed attributes
///
/// This implements the Issue algorithm, which creates a
/// Pointcheval-Sanders signature on the attribute commitment:
///
/// - Select random u ← Zp
/// - Set σ₁ = g^u
/// - Set σ₂ = (g^x · cm)^u
/// - Return credential (cm, cm̃, σ₁, σ₂)
///
/// This signature satisfies the verification equation e(σ₁, X̃ · cm̃) = e(σ₂, g̃) because:
///
/// 1. Left side: e(σ₁, X̃ · cm̃) = e(g^u, g̃^x · cm̃)
/// 2. Right side: e(σ₂, g̃) = e((g^x · cm)^u, g̃)
///
/// By the bilinearity of the pairing, we have:
/// - e(g^u, g̃^x) = e(g, g̃)^(u·x)
/// - e((g^x)^u, g̃) = e(g, g̃)^(u·x)
///
/// And since cm = g^r · ∏ᵢ hᵢ^mᵢ where hᵢ = g^yᵢ, and cm̃ = g̃^r · ∏ᵢ h̃ᵢ^mᵢ where h̃ᵢ = g̃^yᵢ,
/// the verification equation holds for both original and re-randomized credentials.
pub fn issue(
    params: &DomainParams,
    sk: &IssuerSecretKey,
    commitment: &DualCommitment,
) -> Credential {
    let mut rng = StdRng::from_rng(thread_rng()).unwrap();
    let u = Fr::rand(&mut rng);
    
    // Create the first part of the signature: σ₁ = g^u
    let sigma1 = params.g * u;
    
    // Compute the second part: σ₂ = (g^x · cm)^u
    // Where g^x is the issuer's secret key component
    // and cm is the commitment in G1
    let g_x = params.g * sk.x;  // g^x
    let base = g_x + commitment.cm;  // g^x · cm
    let sigma2 = base * u;  // (g^x · cm)^u
    
    Credential {
        commitment: commitment.clone(),
        signature: Signature { sigma1, sigma2 },
    }
}

/// Re-randomize a credential to make it unlinkable
///
/// This implements the ReRand algorithm. 
/// It creates a new credential that:
/// 1. Is valid for the same attributes
/// 2. Cannot be linked to the original credential
/// 3. Can still be verified with the same verification key
///
/// The re-randomization process:
/// - Choose random r' and u'
/// - Set cm' = cm · g^r'
/// - Set cm̃' = cm̃ · g̃^r'
/// - Set σ₁' = (σ₁)^u'
/// - Set σ₂' = (σ₂ · (σ₁)^r')^u'
///
/// The pairing equation still holds for the re-randomized credential because:
///
/// 1. Original: e(σ₁, X̃ · cm̃) = e(σ₂, g̃)
/// 2. Re-randomized: e(σ₁', X̃ · cm̃') = e(σ₂', g̃)
///
/// The magic happens because:
/// - cm' = cm · g^r' and cm̃' = cm̃ · g̃^r' maintain the dual structure
/// - σ₁' = (σ₁)^u' = (g^u)^u' = g^(u·u')
/// - σ₂' = (σ₂ · (σ₁)^r')^u' = ((g^x · cm)^u · (g^u)^r')^u'
///       = ((g^x · cm)^u · g^(u·r'))^u'
///       = ((g^x · cm · g^r')^u)^u'
///       = (g^x · cm')^(u·u')
///
/// This maintains the verification equation while completely unlinking the
/// credential from its original form.
pub fn rerand(
    params: &DomainParams,
    credential: &Credential,
) -> Credential {
    let mut rng = StdRng::from_rng(thread_rng()).unwrap();
    
    // Select random values for re-randomization
    let r_prime = Fr::rand(&mut rng);  // For commitment re-randomization
    let u_prime = Fr::rand(&mut rng);  // For signature re-randomization
    
    // Re-randomize the dual commitment:
    // cm' = cm · g^r'
    // cm̃' = cm̃ · g̃^r'
    let cm_prime = credential.commitment.cm + (params.g * r_prime);
    let cm_tilde_prime = credential.commitment.cm_tilde + (params.g_tilde * r_prime);
    
    // Re-randomize the signature:
    // σ₁' = (σ₁)^u' = (g^u)^u' = g^(u·u')
    let sigma1_prime = credential.signature.sigma1 * u_prime;
    
    // σ₂' = (σ₂ · (σ₁)^r')^u'
    // First calculate (σ₁)^r' = (g^u)^r' = g^(u·r')
    let sigma1_r_prime = credential.signature.sigma1 * r_prime;
    
    // Then calculate σ₂ · (σ₁)^r' = (g^x · cm)^u · g^(u·r')
    let sigma2_plus_term = credential.signature.sigma2 + sigma1_r_prime;
    
    // Finally, raise to power u': ((g^x · cm)^u · g^(u·r'))^u' = (g^x · cm')^(u·u')
    let sigma2_prime = sigma2_plus_term * u_prime;
    
    Credential {
        commitment: DualCommitment { 
            cm: cm_prime, 
            cm_tilde: cm_tilde_prime 
        },
        signature: Signature { 
            sigma1: sigma1_prime, 
            sigma2: sigma2_prime 
        },
    }
}

/// Verify a credential using the issuer's public key
///
/// This implements the Verify algorithm, which checks whether
/// a credential is valid using the pairing equation:
///
/// e(σ₁, X̃ · cm̃) = e(σ₂, g̃)
///
/// This equation holds because:
/// - For the original credential: e(g^u, g̃^x · cm̃) = e((g^x · cm)^u, g̃)
/// - For re-randomized credentials: the same equation holds due to the properties
///   of the re-randomization and bilinear pairings
///
/// Let's break down the verification equation:
/// - σ₁ = g^u                   (first part of signature)
/// - σ₂ = (g^x · cm)^u          (second part of signature)
/// - X̃ = g̃^x                    (issuer public key)
/// - cm̃ = g̃^r · ∏ᵢ h̃ᵢ^mᵢ        (commitment in G2)
///
/// The left side: e(g^u, g̃^x · cm̃)
/// The right side: e((g^x · cm)^u, g̃)
///
/// These are equal due to the bilinearity property of pairings:
/// e(g^a, g̃^b) = e(g, g̃)^(a·b)
///
/// This verification works without revealing the attributes or linking to other
/// credential presentations.
pub fn verify(
    params: &DomainParams,
    pk: &IssuerPublicKey,
    credential: &Credential,
) -> Result<()> {
    // Extract the components needed for verification
    let sigma1 = credential.signature.sigma1;  // σ₁ = g^u
    let sigma2 = credential.signature.sigma2;  // σ₂ = (g^x · cm)^u
    let g_tilde = params.g_tilde;              // g̃ (generator of G2)
    
    // X̃ · cm̃ = g̃^x · cm̃ = g̃^x · (g̃^r · ∏ᵢ h̃ᵢ^mᵢ)
    let x_tilde_times_cm_tilde = pk.x_tilde + credential.commitment.cm_tilde;
    
    // Compute the left side of the equation: e(σ₁, X̃ · cm̃)
    let left_side = Bls12_381::pairing(sigma1, x_tilde_times_cm_tilde);
    
    // Compute the right side of the equation: e(σ₂, g̃)
    let right_side = Bls12_381::pairing(sigma2, g_tilde);
    
    // Verify that e(σ₁, X̃ · cm̃) = e(σ₂, g̃)
    if left_side == right_side {
        Ok(())
    } else {
        Err(CredentialError::VerificationFailed)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_credential_flow() {
        // Setup
        let params = setup();
        
        // Create issuer keys for 3 attributes
        let issuer_keys = keygen(&params, 3);
        let (issuer_sk, issuer_pk) = (issuer_keys.0.clone(), issuer_keys.1.clone());
        
        // Create user attributes
        let mut rng = StdRng::from_rng(thread_rng()).unwrap();
        let attributes: Vec<Fr> = (0..3)
            .map(|_| Fr::rand(&mut rng))
            .collect();
        
        // Create commitment randomness
        let randomness = Fr::rand(&mut rng);
        
        // Create dual commitment
        let commitment = dual_commit(&params, &issuer_keys, &attributes, &randomness);
        
        // Issue credential
        let credential = issue(&params, &issuer_sk, &commitment);
        
        // Verify original credential
        assert!(verify(&params, &issuer_pk, &credential).is_ok());
        
        // Re-randomize credential
        let rerandomized_cred = rerand(&params, &credential);
        
        // Verify re-randomized credential
        assert!(verify(&params, &issuer_pk, &rerandomized_cred).is_ok());
        
        // Check that the re-randomized credential is different but still valid
        assert!(credential.signature.sigma1 != rerandomized_cred.signature.sigma1);
        assert!(credential.signature.sigma2 != rerandomized_cred.signature.sigma2);
    }
}