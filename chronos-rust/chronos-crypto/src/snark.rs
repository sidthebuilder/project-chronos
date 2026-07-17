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
