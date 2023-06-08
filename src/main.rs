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
use hex;
use poseidon_circuit::poseidon::Pow5Chip;
use poseidon_circuit::{hash::*, DEFAULT_STEP};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::env;

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

fn main() {
    let args: Vec<String> = env::args().collect();
    let controls_index = args
        .iter()
        .position(|arg| arg == "--controls")
        .expect("Missing --controls parameter");
    let inputs_index = args
        .iter()
        .position(|arg| arg == "--inputs")
        .expect("Missing --inputs parameter");
    let controls: Vec<u64> = args[controls_index + 1]
        .split(",")
        .map(|s| s.parse::<u64>().unwrap())
        .collect();
    let inputs: Vec<u64> = args[inputs_index + 1]
        .split(",")
        .map(|s| s.parse::<u64>().unwrap())
        .collect();

    println!("controls: {:?}", controls);
    println!("inputs: {:?}", inputs);

    // change controls and inputs to PoseidonHashTable
    let mut poseidon_inputs: Vec<[Fp; 2]> = vec![];
    let mut poseidon_controls: Vec<u64> = vec![];
    for i in (0..inputs.len()).step_by(2) {
        poseidon_inputs.push([Fp::from(inputs[i]), Fp::from(inputs[i + 1])]);
    }
    for i in controls.iter() {
        poseidon_controls.push(*i);
    }

    println!("poseidon_inputs: {:?}", poseidon_inputs);
    println!("poseidon_controls: {:?}", poseidon_controls);

    let poseidon_hash_table = PoseidonHashTable {
        inputs: poseidon_inputs,
        controls: poseidon_controls,
        ..Default::default()
    };

    let k = 8;

    let params = Params::<Bn256>::unsafe_setup(k);
    let os_rng = ChaCha8Rng::from_seed([101u8; 32]);
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    let circuit = TestCircuit(poseidon_hash_table, 4);

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
    // print proof with hex format
    println!("{}", hex::encode(proof_script));
    // let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_script[..]);
}
