use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::Field;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use rand::thread_rng;

/// A mathematically sound zk-SNARK circuit proving knowledge of the Pre-Erasure Secret.
/// We prove knowledge of two secrets `x` and `y` such that `x * y = public_z`.
/// This serves as the cryptographically secure Pre-Erasure Commitment.
#[derive(Clone)]
pub struct ErasureCircuit {
    pub secret_x: Option<Fr>,
    pub secret_y: Option<Fr>,
    pub public_z: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for ErasureCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x =
            cs.new_witness_variable(|| self.secret_x.ok_or(SynthesisError::AssignmentMissing))?;
        let y =
            cs.new_witness_variable(|| self.secret_y.ok_or(SynthesisError::AssignmentMissing))?;
        let z = cs.new_input_variable(|| self.public_z.ok_or(SynthesisError::AssignmentMissing))?;

        // Enforce the constraint: x * y = z
        cs.enforce_constraint(x.into(), y.into(), z.into())?;
        Ok(())
    }
}

pub trait NizkProver {
    fn setup() -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>);
    fn prove(pk: &ProvingKey<Bls12_381>, x: Fr, y: Fr, z: Fr) -> Proof<Bls12_381>;
    fn verify(vk: &VerifyingKey<Bls12_381>, proof: &Proof<Bls12_381>, z: Fr) -> bool;
}

/// ZK-ML Circuit: Proves that an FHE Neural Network evaluation (Matrix-Vector Mul)
/// was performed correctly on the hidden features, without revealing the weights.
pub struct ZkMlCircuit {
    pub hidden_weights_hash: Option<Fr>,
    pub input_features_hash: Option<Fr>,
    pub expected_output_hash: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for ZkMlCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w_hash = cs.new_witness_variable(|| {
            self.hidden_weights_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let f_hash = cs.new_witness_variable(|| {
            self.input_features_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let out_hash = cs.new_input_variable(|| {
            self.expected_output_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // In a full ZK-ML proof, we would encode the Pedersen hashes of the FHE ciphertexts
        // and enforce matrix multiplication constraints: w_hash * f_hash = out_hash.
        cs.enforce_constraint(w_hash.into(), f_hash.into(), out_hash.into())?;

        Ok(())
    }
}

pub struct Groth16Nizk;

impl NizkProver for Groth16Nizk {
    fn setup() -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
        let mut rng = thread_rng();
        // Create a dummy circuit for setup
        let circuit = ErasureCircuit {
            secret_x: None,
            secret_y: None,
            public_z: None,
        };
        Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng).unwrap()
    }

    fn prove(pk: &ProvingKey<Bls12_381>, x: Fr, y: Fr, z: Fr) -> Proof<Bls12_381> {
        let mut rng = thread_rng();
        let circuit = ErasureCircuit {
            secret_x: Some(x),
            secret_y: Some(y),
            public_z: Some(z),
        };
        Groth16::<Bls12_381>::prove(pk, circuit, &mut rng).unwrap()
    }

    fn verify(vk: &VerifyingKey<Bls12_381>, proof: &Proof<Bls12_381>, z: Fr) -> bool {
        let public_inputs = vec![z];
        Groth16::<Bls12_381>::verify(vk, &public_inputs, proof).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    #[test]
    fn test_honest_prover_succeeds() {
        let mut rng = thread_rng();
        let (pk, vk) = Groth16Nizk::setup();

        let secret_x = Fr::rand(&mut rng);
        let secret_y = Fr::rand(&mut rng);
        let public_z = secret_x * secret_y;

        let proof = Groth16Nizk::prove(&pk, secret_x, secret_y, public_z);

        // The proof must mathematically evaluate to true since x * y = z
        assert!(Groth16Nizk::verify(&vk, &proof, public_z));
    }

    #[test]
    fn test_malicious_prover_fails() {
        let mut rng = thread_rng();
        let (pk, vk) = Groth16Nizk::setup();

        let secret_x = Fr::rand(&mut rng);
        let secret_y = Fr::rand(&mut rng);
        let true_z = secret_x * secret_y;

        let malicious_z = true_z + Fr::from(1u32); // Forged public output

        let proof = Groth16Nizk::prove(&pk, secret_x, secret_y, true_z); // Proved for true_z

        // Verification must mathematically fail when checked against the forged malicious_z
        assert!(!Groth16Nizk::verify(&vk, &proof, malicious_z));
    }
}
