use anonymous_creds::{
    setup, keygen, dual_commit, issue, rerand, verify
};
use ark_bls12_381::Fr;
use ark_std::{UniformRand, rand::SeedableRng};
use rand::{thread_rng, rngs::StdRng};

fn main() {
    println!("Re-randomizable Credentials Demo");
    println!("================================");
    
    // Setup phase
    println!("\n[1] Setting up domain parameters...");
    let domain_params = setup();
    
    // Issuer setup
    println!("\n[2] Generating issuer keys...");
    let num_attributes = 2;  // We'll use two attributes: age and membership level
    let issuer_keys = keygen(&domain_params, num_attributes);
    let (issuer_sk, issuer_pk) = (issuer_keys.0.clone(), issuer_keys.1.clone());
    println!("    Issuer keys generated for {} attributes", num_attributes);
    
    // User attributes
    println!("\n[3] Creating user attributes...");
    let mut rng = StdRng::from_rng(thread_rng()).unwrap();
    
    // For demonstration purposes, we'll create random attributes
    let attr1 = Fr::rand(&mut rng);
    let attr2 = Fr::rand(&mut rng);
    let attributes = vec![attr1, attr2];
    
    println!("    User attributes created (random values for demo)");
    
    // Create commitment randomness
    let randomness = Fr::rand(&mut rng);
    
    // Create commitment
    println!("\n[4] Creating commitment to attributes...");
    let commitment = dual_commit(&domain_params, &issuer_keys, &attributes, &randomness);
    
    // Issue credential
    println!("\n[5] Issuer is creating credential...");
    let credential = issue(&domain_params, &issuer_sk, &commitment);
    println!("    Credential issued successfully");
    
    // Verify original credential
    println!("\n[6] Verifying original credential...");
    match verify(&domain_params, &issuer_pk, &credential) {
        Ok(_) => println!("    Original credential verified successfully!"),
        Err(_) => println!("    Verification failed!"),
    }
    
    // Re-randomize credential
    println!("\n[7] Re-randomizing credential...");
    let rerandomized_cred = rerand(&domain_params, &credential);
    println!("    Credential re-randomized");
    
    // Verify re-randomized credential
    println!("\n[8] Verifying re-randomized credential...");
    match verify(&domain_params, &issuer_pk, &rerandomized_cred) {
        Ok(_) => println!("    Re-randomized credential verified successfully!"),
        Err(_) => println!("    Verification failed!"),
    }
    
    // Show unlinkability
    println!("\n[9] Demonstrating unlinkability...");
    if credential.signature.sigma1 != rerandomized_cred.signature.sigma1 {
        println!("    Original and re-randomized credentials have different signatures");
        println!("    Even though both credentials are for the same attributes,");
        println!("    they cannot be linked due to re-randomization!");
    } else {
        println!("    Error: Re-randomization did not change the signature!");
    }
}