/// Re-randomizable Anonymous Credentials
/// 
/// Implements the Re-randomizable Credentials scheme from:
/// https://decentralizedthoughts.github.io/2023-01-08-re-rand-cred/
/// 
/// This privacy-preserving credential system:
/// - Uses bilinear pairings on BLS12-381 curve via arkworks
/// - Includes trusted setup for attribute generators
/// - Supports unlinkable credential presentations via re-randomization

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
use std::error::Error as StdError;

// Include the trusted setup module
pub mod trusted_setup;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid parameters")]
    InvalidParameters,
    #[error("Trusted setup error: {0}")]
    TrustedSetupError(String),
}

impl From<Box<dyn StdError>> for CredentialError {
    fn from(err: Box<dyn StdError>) -> Self {
        CredentialError::TrustedSetupError(err.to_string())
    }
}

type Result<T> = std::result::Result<T, CredentialError>;

/// Domain parameters for the credential system
///
/// Uses bilinear groups G1 and G2 from BLS12-381 curve with 
/// structured reference strings (SRS) from trusted setup.
#[derive(Clone, Debug)]
pub struct DomainParams {
    /// Generator of G1
    pub g: G1Projective,
    
    /// Generator of G2
    pub g_tilde: G2Projective,
    
    /// G1 SRS: [g, g^α, g^(α^2), ...]
    pub g1_srs: Vec<G1Projective>,
    
    /// G2 SRS: [g̃, g̃^α, g̃^(α^2), ...]
    pub g2_srs: Vec<G2Projective>,
    
    /// Maximum number of attributes supported
    pub max_attributes: usize,
}

impl Default for DomainParams {
    fn default() -> Self {
        // For testing only - prefer setup() for proper usage
        let trusted_setup = trusted_setup::generate_trusted_setup(10);
        
        Self {
            g: G1Projective::generator(),
            g_tilde: G2Projective::generator(),
            g1_srs: trusted_setup.g1_srs,
            g2_srs: trusted_setup.g2_srs,
            max_attributes: trusted_setup.max_attributes,
        }
    }
}

/// Issuer secret key for the credential system
///
/// Contains master secret x and attribute generators h from trusted setup
#[derive(Clone, Debug)]
pub struct IssuerSecretKey {
    x: Fr,                     // Master secret
    y: Vec<Fr>,                // Not used with trusted setup
    h: Vec<G1Projective>,      // G1 attribute generators
}

/// Issuer public key for verification
///
/// Contains public elements for the Pointcheval-Sanders signature verification
#[derive(Clone, Debug)]
pub struct IssuerPublicKey {
    x_tilde: G2Projective,        // g_tilde^x
    y_tilde: Vec<G2Projective>,   // For verification compatibility
    h_tilde: Vec<G2Projective>,   // G2 attribute generators
}

/// Dual Pedersen commitment in both G1 and G2
///
/// Computed as:
/// - cm = g^r · ∏ᵢ₌₁ᵏ hᵢ^mᵢ in G1
/// - cm̃ = g̃^r · ∏ᵢ₌₁ᵏ h̃ᵢ^mᵢ in G2
#[derive(Clone, Debug)]
pub struct DualCommitment {
    cm: G1Projective,       // G1 commitment
    cm_tilde: G2Projective, // G2 commitment
}

/// Pointcheval-Sanders signature (σ₁, σ₂)
///
/// - σ₁ = g^u
/// - σ₂ = (g^x · cm)^u
#[derive(Clone, Debug)]
pub struct Signature {
    pub sigma1: G1Projective,   // g^u
    pub sigma2: G1Projective,   // (g^x · cm)^u
}

/// Credential containing a dual commitment and signature
///
/// Can be re-randomized while maintaining verifiability
#[derive(Clone, Debug)]
pub struct Credential {
    pub commitment: DualCommitment,
    pub signature: Signature,
}

/// Setup function: Generate domain parameters from trusted setup
///
/// Uses a trusted setup procedure to generate attribute generators
/// where no party knows the discrete logarithm relationships.
///
/// Parameters:
/// - `trusted_setup_path`: Path to trusted setup file (creates new one if missing)
/// - `max_attributes`: Maximum number of attributes supported
pub fn setup_with_trusted_params(trusted_setup_path: &str, max_attributes: usize) -> Result<DomainParams> {
    // Ensure the trusted setup file exists or create it
    let trusted_params = trusted_setup::ensure_trusted_setup(trusted_setup_path, max_attributes)
        .map_err(|e| CredentialError::TrustedSetupError(e.to_string()))?;
    
    Ok(DomainParams {
        g: G1Projective::generator(),
        g_tilde: G2Projective::generator(),
        g1_srs: trusted_params.g1_srs,
        g2_srs: trusted_params.g2_srs,
        max_attributes: trusted_params.max_attributes,
    })
}

/// Setup function with default values for testing and demos
pub fn setup() -> DomainParams {
    // Use a default path in the current directory
    match setup_with_trusted_params("./trusted_setup.params", 10) {
        Ok(params) => params,
        Err(_) => {
            println!("Warning: Using default trusted setup for demo purposes.");
            DomainParams::default() // Fallback to default implementation
        }
    }
}

/// Generate issuer keys from trusted setup
///
/// Creates:
/// - Secret key: master secret x
/// - Public key: verification elements g̃^x and attribute generators
///
/// Uses generators from trusted setup SRS to ensure security of Pedersen commitments
pub fn keygen(params: &DomainParams, num_attributes: usize) -> (IssuerSecretKey, IssuerPublicKey) {
    if num_attributes > params.max_attributes {
        panic!("Number of attributes exceeds the maximum supported in the trusted setup");
    }
    
    let mut rng = StdRng::from_rng(thread_rng()).unwrap();
    
    // Generate master secret x
    let x = Fr::rand(&mut rng);
    
    // We don't need to generate y values anymore, since we'll use the trusted setup
    // generators directly instead of g^y_i
    let y = Vec::new(); // Kept for API compatibility, but not used
    
    // Use attribute generators from the trusted setup
    // Skip the first element (which is the base generator)
    let h = params.g1_srs[1..=num_attributes].to_vec();
    
    // Compute public verification key
    let x_tilde = params.g_tilde * x;
    
    // Use attribute generators from G2 trusted setup
    // Skip the first element (which is the base generator)
    let h_tilde = params.g2_srs[1..=num_attributes].to_vec();
    
    // For compatibility with the PS signature scheme verification
    // We no longer derive these from secret keys
    let y_tilde = h_tilde.clone();
    
    (
        IssuerSecretKey { x, y, h },
        IssuerPublicKey { x_tilde, y_tilde, h_tilde }
    )
}

/// Create a dual Pedersen commitment to attributes
///
/// Computes commitments in both G1 and G2:
/// - cm = g^r · ∏ᵢ₌₁ᵏ hᵢ^mᵢ in G1
/// - cm̃ = g̃^r · ∏ᵢ₌₁ᵏ h̃ᵢ^mᵢ in G2
///
/// Uses attribute generators from trusted setup for security.
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

/// Issue a Pointcheval-Sanders signature on committed attributes
///
/// Creates signature (σ₁, σ₂) where:
/// - σ₁ = g^u  (random u)
/// - σ₂ = (g^x · cm)^u
///
/// Verification works via the pairing equation: e(σ₁, X̃ · cm̃) = e(σ₂, g̃)
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
/// Creates a new credential that:
/// 1. Validates for the same attributes
/// 2. Cannot be linked to the original credential
/// 
/// Process:
/// - Choose random r' and u'
/// - cm' = cm · g^r'
/// - cm̃' = cm̃ · g̃^r'
/// - σ₁' = (σ₁)^u'
/// - σ₂' = (σ₂ · (σ₁)^r')^u'
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

/// Verify a credential using the pairing equation
///
/// Checks if: e(σ₁, X̃ · cm̃) = e(σ₂, g̃)
///
/// Works for both original and re-randomized credentials due to
/// the bilinear properties of the pairing.
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
    use std::fs;
    
    #[test]
    fn test_trusted_setup_generation() {
        // Test creating a new trusted setup
        let test_path = "./test_trusted_setup.params";
        
        // Clean up any existing file
        let _ = fs::remove_file(test_path);
        
        // Generate a new trusted setup
        let trusted_params = trusted_setup::generate_trusted_setup(5);
        assert_eq!(trusted_params.max_attributes, 5);
        assert_eq!(trusted_params.g1_srs.len(), 6); // Base generator + 5 attribute generators
        assert_eq!(trusted_params.g2_srs.len(), 6);
        
        // Save it
        let result = trusted_setup::save_trusted_setup(&trusted_params, test_path);
        assert!(result.is_ok());
        
        // Load it back
        let loaded_params = trusted_setup::load_trusted_setup(test_path);
        assert!(loaded_params.is_ok());
        
        // Clean up
        let _ = fs::remove_file(test_path);
    }
    
    #[test]
    fn test_credential_flow_with_trusted_setup() {
        // Setup with a fresh trusted setup for testing
        let test_path = "./test_cred_flow.params";
        let _ = fs::remove_file(test_path); // Clean up any existing file
        
        let params = match setup_with_trusted_params(test_path, 5) {
            Ok(p) => p,
            Err(_) => {
                panic!("Failed to create trusted setup");
            }
        };
        
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
        
        // Clean up
        let _ = fs::remove_file(test_path);
    }
    
    #[test]
    fn test_credential_flow() {
        // This is the original test using the default setup - kept for compatibility
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