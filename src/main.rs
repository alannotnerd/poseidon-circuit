use std::fs::File;
use std::io::BufReader;

use circuit_cli::CliOperator;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr as Fp, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::{
    KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG as ParamsVerifier,
};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use poseidon_circuit::poseidon::Pow5Chip;
use poseidon_circuit::{hash::*, DEFAULT_STEP};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

struct TestCircuit(PoseidonHashTable<Fp>, usize);

// test circuit derived from table data
impl Circuit<Fp> for TestCircuit {
    type Config = SpongeConfig<Fp, Pow5Chip<Fp, 3, 2>>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self(PoseidonHashTable::default(), self.1)
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let hash_tbl = [0; 5].map(|_| meta.advice_column());
        SpongeConfig::configure_sub(meta, hash_tbl, DEFAULT_STEP)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = SpongeChip::<Fp, DEFAULT_STEP, Pow5Chip<Fp, 3, 2>>::construct(
            config,
            &self.0,
            self.1,
            false,
            Some(Fp::from(42u64)),
        );
        chip.load(&mut layouter)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CliArgs {
    pub k: Option<u32>,
    pub inputs: Option<Vec<(u64, u64)>>,
    pub controls: Option<Vec<u64>>,
    pub calcs: Option<usize>,
    pub verify: Option<bool>,
    pub persist: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CliVerifyArgs {
    pub calcs: Option<usize>,
}

fn poseidon(
    args: CliArgs,
    params_reader: Option<BufReader<File>>,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let k = args.k.unwrap_or(8);

    let inputs = args.inputs.unwrap_or(vec![(1, 2), (30, 1), (65536, 0)]);
    let controls = args.controls.unwrap_or(vec![0, 46, 14]);
    let calcs = args.calcs.unwrap_or(4);

    let mut poseidon_inputs: Vec<[Fp; 2]> = vec![];
    for input in inputs.iter() {
        poseidon_inputs.push([Fp::from(input.0), Fp::from(input.1)]);
    }
    let poseidon_hash_table = PoseidonHashTable {
        inputs: poseidon_inputs,
        controls: controls,
        ..Default::default()
    };

    let params: ParamsKZG<Bn256>;
    if let Some(mut params_r) = params_reader {
        params = Params::read::<_>(&mut params_r).expect("Failed to read params");
    } else {
        params = ParamsKZG::<Bn256>::unsafe_setup(k);
    }

    let os_rng = ChaCha8Rng::from_seed([101u8; 32]);
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    let circuit = TestCircuit(poseidon_hash_table, calcs);

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        os_rng,
        &mut transcript,
    )
    .unwrap();

    let proof_script = transcript.finalize();

    if args.verify.unwrap_or(true) {
        verify_generated_proof(params.clone(), calcs, &proof_script)?;
    }

    let mut buf = Vec::new();
    params.write(&mut buf).expect("Failed to write params");

    Ok((proof_script, buf))
}

fn verify_generated_proof(
    params: ParamsKZG<Bn256>,
    calcs: usize,
    proof_script: &[u8],
) -> Result<bool, Error> {
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_script[..]);
    let verifier_params: ParamsVerifier<Bn256> = params.verifier_params().clone();
    let strategy = SingleStrategy::new(&params);
    let circuit = TestCircuit(PoseidonHashTable::default(), calcs);
    let vk = keygen_vk(&params, &circuit)?;

    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
        &verifier_params,
        &vk,
        strategy,
        &[&[]],
        &mut transcript,
    )?;

    Ok(true)
}

fn verify_poseidon(
    args: CliVerifyArgs,
    params: ParamsKZG<Bn256>,
    proof_script: &[u8],
) -> Result<bool, Error> {
    let calcs = args.calcs.unwrap_or(4);
    verify_generated_proof(params, calcs, proof_script)
}

struct Operator;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    circuit_cli::run(Operator)?;
    Ok(())
}

impl CliOperator<CliArgs, CliVerifyArgs> for Operator {
    fn create_proof(
        &self,
        args: CliArgs,
        params_reader: Option<BufReader<File>>,
    ) -> circuit_cli::Result<(Vec<u8>, Vec<u8>)> {
        poseidon(args, params_reader).map_err(|e| circuit_cli::Error::CliLogicError(e.to_string()))
    }

    fn verify_proof(
        &self,
        args: CliVerifyArgs,
        params_reader: Option<BufReader<File>>,
        proof: &[u8],
    ) -> circuit_cli::Result<bool> {
        let params: ParamsKZG<Bn256> = Params::read::<_>(&mut params_reader.ok_or(
            circuit_cli::Error::CliLogicError("params reader is None".to_string()),
        )?)
        .expect("Failed to read params");
        verify_poseidon(args, params, proof)
            .map_err(|e| circuit_cli::Error::CliLogicError(e.to_string()))
    }
}
