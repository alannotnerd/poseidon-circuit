use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr as Fp, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG as Params};
use halo2_proofs::poly::kzg::multiopen::ProverSHPLONK;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
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
    pub draw_graph: Option<bool>,
    pub k: Option<u32>,
    pub inputs: Option<Vec<u64>>,
    pub controls: Option<Vec<u64>>,
    pub calcs: Option<usize>,
    pub verify: Option<bool>,
    pub persist: Option<bool>,
}

fn poseidon(args: CliArgs) -> Result<Vec<u8>, Error> {
    let k = args.k.unwrap_or(8);

    let inputs = args.inputs.unwrap_or(vec![1, 2, 30, 1, 65536, 0]);
    let controls = args.controls.unwrap_or(vec![0, 46, 14]);
    let calcs = args.calcs.unwrap_or(4);

    let mut poseidon_inputs: Vec<[Fp; 2]> = vec![];
    for i in (0..inputs.len()).step_by(2) {
        poseidon_inputs.push([Fp::from(inputs[i]), Fp::from(inputs[i + 1])]);
    }
    let poseidon_hash_table = PoseidonHashTable {
        inputs: poseidon_inputs,
        controls: controls,
        ..Default::default()
    };

    let params = Params::<Bn256>::unsafe_setup(k);
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
    // println!("{}", hex::encode(proof_script.clone()));

    Ok(proof_script)
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    circuit_cli::run(|args: CliArgs| {
        poseidon(args).map_err(|e| circuit_cli::Error::CliLogicError(e.to_string()))
    })?;
    Ok(())
}
