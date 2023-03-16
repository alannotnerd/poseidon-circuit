//! The hash circuit base on poseidon.

use crate::poseidon::primitives::{
    ConstantLengthIden3, Domain, Hash, P128Pow5T3, Spec, VariableLengthIden3,
};
use halo2_proofs::ff::{FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::bn256::Fr;

/// indicate an field can be hashed in merkle tree (2 Fields to 1 Field)
pub trait Hashable: FromUniformBytes<64> + Ord {
    /// the spec type used in circuit for this hashable field
    type SpecType: Spec<Self, 3, 2>;
    /// the domain type used for hash calculation
    type DomainType: Domain<Self, 2>;

    /// execute hash for any sequence of fields
    fn hash(inp: [Self; 2]) -> Self;
    /// obtain the rows consumed by each circuit block
    fn hash_block_size() -> usize {
        1 + Self::SpecType::full_rounds() + (Self::SpecType::partial_rounds() + 1) / 2
    }
    /// init a hasher used for hash
    fn hasher() -> Hash<Self, Self::SpecType, Self::DomainType, 3, 2> {
        Hash::<Self, Self::SpecType, Self::DomainType, 3, 2>::init()
    }
}

/// indicate an message stream constructed by the field can be hashed, commonly
/// it just need to update the Domain
pub trait MessageHashable: Hashable {
    /// the domain type used for message hash
    type DomainType: Domain<Self, 2>;
    /// hash message, if cap is not provided, it commonly use the len of msg
    fn hash_msg(msg: &[Self], cap: Option<u64>) -> Self;
    /// init a hasher used for hash message
    fn msg_hasher(
    ) -> Hash<Self, <Self as Hashable>::SpecType, <Self as MessageHashable>::DomainType, 3, 2> {
        Hash::<Self, <Self as Hashable>::SpecType, <Self as MessageHashable>::DomainType, 3, 2>::init()
    }
}

impl Hashable for Fr {
    type SpecType = P128Pow5T3<Self>;
    type DomainType = ConstantLengthIden3<2>;

    fn hash(inp: [Self; 2]) -> Self {
        Self::hasher().hash(inp)
    }
}

impl MessageHashable for Fr {
    type DomainType = VariableLengthIden3;

    fn hash_msg(msg: &[Self], cap: Option<u64>) -> Self {
        Self::msg_hasher().hash_with_cap(msg, cap.unwrap_or(msg.len() as u64))
    }
}

use crate::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord, Var};
use halo2_proofs::{
    circuit::{Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, TableColumn},
    poly::Rotation,
};

/// The config for poseidon hash circuit
#[derive(Clone, Debug)]
pub struct PoseidonHashConfig<Fp: PrimeField> {
    permute_config: Pow5Config<Fp, 3, 2>,
    hash_table: [Column<Advice>; 4],
    hash_table_aux: [Column<Advice>; 6],
    control_aux: Column<Advice>,
    s_sponge_continue: Column<Advice>,
    constants: [Column<Fixed>; 6],
    control_step_range: TableColumn,
    s_table: Selector,
}

impl<Fp: Hashable> PoseidonHashConfig<Fp> {
    /// obtain the commitment index of hash table
    pub fn commitment_index(&self) -> [usize; 4] {
        self.hash_table.map(|col| col.index())
    }

    /// obtain the hash_table columns
    pub fn hash_tbl_cols(&self) -> [Column<Advice>; 4] {
        self.hash_table
    }

    /// build configure for sub circuit
    pub fn configure_sub(
        meta: &mut ConstraintSystem<Fp>,
        hash_table: [Column<Advice>; 4],
        step: usize,
    ) -> Self {
        let state = [0; 3].map(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let constants = [0; 6].map(|_| meta.fixed_column());
        let s_table = meta.complex_selector();

        let hash_table_aux = [0; 6].map(|_| meta.advice_column());
        for col in hash_table_aux.iter().chain(hash_table[0..1].iter()) {
            meta.enable_equality(*col);
        }
        meta.enable_equality(constants[0]);

        let control = hash_table[3];
        let s_sponge_continue = meta.advice_column();
        meta.enable_equality(s_sponge_continue);
        let control_aux = meta.advice_column();
        let control_step_range = meta.lookup_table_column();

        let state_in = &hash_table_aux[0..3];
        let state_for_next_in = &hash_table_aux[3..5];
        let hash_out = hash_table_aux[5];
        let hash_inp = &hash_table[1..3];
        let hash_index = hash_table[0];

        meta.create_gate("control constrain", |meta| {
            let s_enable = meta.query_selector(s_table);
            let ctrl = meta.query_advice(control, Rotation::cur());
            let ctrl_bool = ctrl.clone() * meta.query_advice(control_aux, Rotation::cur());
            let s_continue = meta.query_advice(s_sponge_continue, Rotation::cur());

            vec![
                s_enable.clone() * ctrl * (Expression::Constant(Fp::ONE) - ctrl_bool.clone()),
                s_enable * s_continue * (Expression::Constant(Fp::ONE) - ctrl_bool),
            ]
        });

        meta.create_gate("control step", |meta| {
            let s_enable = meta.query_selector(s_table);
            let s_continue = meta.query_advice(s_sponge_continue, Rotation::cur());
            let ctrl = meta.query_advice(control, Rotation::cur());
            let ctrl_prev = meta.query_advice(control, Rotation::prev());

            vec![
                s_enable
                    * s_continue
                    * (ctrl + Expression::Constant(Fp::from_u128(step as u128)) - ctrl_prev),
            ]
        });

        meta.lookup("control range check", |meta| {
            let s_enable = meta.query_selector(s_table);
            let s_continue = meta.query_advice(s_sponge_continue, Rotation::cur());
            let ctrl = meta.query_advice(control, Rotation::prev());

            vec![(
                s_enable * (Expression::Constant(Fp::ONE) - s_continue) * ctrl,
                control_step_range,
            )]
        });

        meta.create_gate("hash index constrain", |meta| {
            let s_enable = meta.query_selector(s_table);
            let s_continue_hash = meta.query_advice(s_sponge_continue, Rotation::cur());
            let hash_ind = meta.query_advice(hash_index, Rotation::cur());
            let hash_prev = meta.query_advice(hash_index, Rotation::prev());
            let hash_out = meta.query_advice(hash_out, Rotation::prev());

            vec![
                s_enable.clone() * s_continue_hash.clone() * (hash_ind - hash_prev.clone()),
                s_enable
                    * (Expression::Constant(Fp::ONE) - s_continue_hash)
                    * (hash_out - hash_prev),
            ]
        });

        meta.create_gate("input constrain", |meta| {
            let s_enable = meta.query_selector(s_table);
            let s_continue_hash = meta.query_advice(s_sponge_continue, Rotation::cur());

            // external input: if not new hash, input must add prev state
            let mut ret: Vec<_> = state_in[1..]
                .iter()
                .zip(state_for_next_in.iter())
                .zip(hash_inp.iter())
                .map(|((inp, prev_inp), ext_inp)| {
                    let inp = meta.query_advice(*inp, Rotation::cur());
                    let prev_inp = meta.query_advice(*prev_inp, Rotation::prev());
                    let ext_inp = meta.query_advice(*ext_inp, Rotation::cur());

                    s_enable.clone() * (prev_inp * s_continue_hash.clone() + ext_inp - inp)
                })
                .collect();

            assert_eq!(hash_inp.len(), ret.len());

            let inp_hash = meta.query_advice(state_in[0], Rotation::cur());
            let inp_hash_prev = meta.query_advice(hash_out, Rotation::prev());
            let inp_hash_init = meta.query_advice(control, Rotation::cur());

            // hash output: must inherit prev state or apply current control flag (for new hash)
            ret.push(
                s_enable.clone()
                    * (Expression::Constant(Fp::ONE) - s_continue_hash.clone())
                    * (inp_hash.clone() - inp_hash_init),
            );
            ret.push(s_enable * s_continue_hash * (inp_hash - inp_hash_prev));
            ret
        });

        Self {
            permute_config: Pow5Chip::configure::<Fp::SpecType>(
                meta,
                state,
                partial_sbox,
                constants[..3].try_into().unwrap(), //rc_a
                constants[3..].try_into().unwrap(), //rc_b
            ),
            hash_table,
            hash_table_aux,
            control_aux,
            constants,
            control_step_range,
            s_table,
            s_sponge_continue,
        }
    }
}

/// Poseidon hash table
#[derive(Clone, Default, Debug)]
pub struct PoseidonHashTable<Fp> {
    /// the input messages for hashes
    pub inputs: Vec<[Fp; 2]>,
    /// the control flag for each permutation
    pub controls: Vec<Fp>,
    /// the expected hash output for checking
    pub checks: Vec<Option<Fp>>,
}

impl<Fp: PrimeField> PoseidonHashTable<Fp> {
    /// Add common inputs
    pub fn constant_inputs<'d>(&mut self, src: impl IntoIterator<Item = &'d [Fp; 2]>) {
        let mut new_inps: Vec<_> = src.into_iter().copied().collect();
        self.inputs.append(&mut new_inps);
    }

    /// Add common inputs with expected hash as check
    pub fn constant_inputs_with_check<'d>(
        &mut self,
        src: impl IntoIterator<Item = &'d (Fp, Fp, Fp)>,
    ) {
        // align input and checks
        self.checks.resize(self.inputs.len(), None);

        for (a, b, c) in src {
            self.inputs.push([*a, *b]);
            self.checks.push(Some(*c));
        }
    }

    /// Add a series of inputs from a field stream
    pub fn stream_inputs<'d>(
        &mut self,
        src: impl IntoIterator<Item = &'d [Fp; 2]>,
        ctrl_start: u64,
        step: usize,
    ) {
        let mut new_inps: Vec<_> = src.into_iter().copied().collect();
        let mut ctrl_series: Vec<_> = std::iter::successors(Some(ctrl_start), |n| {
            if *n > (step as u64) {
                Some(n - step as u64)
            } else {
                None
            }
        })
        .map(Fp::from)
        .take(new_inps.len())
        .collect();

        assert_eq!(new_inps.len(), ctrl_series.len());
        self.inputs.append(&mut new_inps);
        self.controls.append(&mut ctrl_series);
    }
}

/// Represent the chip for Poseidon hash table
#[derive(Debug)]
pub struct PoseidonHashChip<'d, Fp: PrimeField, const STEP: usize> {
    calcs: usize,
    data: &'d PoseidonHashTable<Fp>,
    config: PoseidonHashConfig<Fp>,
}

impl<'d, Fp: Hashable, const STEP: usize> PoseidonHashChip<'d, Fp, STEP> {
    ///construct the chip
    pub fn construct(
        config: PoseidonHashConfig<Fp>,
        data: &'d PoseidonHashTable<Fp>,
        calcs: usize,
    ) -> Self {
        Self {
            calcs,
            data,
            config,
        }
    }

    /// load the table into circuit under the specified config
    pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        let config = &self.config;
        let constants_cell = layouter.assign_region(
            || "constant heading",
            |mut region| {
                let c0 = region.assign_fixed(
                    || "constant zero",
                    config.constants[0],
                    0,
                    || Value::known(Fp::ZERO),
                )?;

                Ok([c0])
            },
        )?;

        layouter.assign_table(
            || "STEP range check",
            |mut table| {
                (0..STEP + 1).into_iter().try_for_each(|i| {
                    table
                        .assign_cell(
                            || "STEP range check",
                            config.control_step_range,
                            i,
                            || Value::known(Fp::from_u128(i as u128)),
                        )
                        .map(|_| ())
                })
            },
        )?;

        let data = self.data;
        let (states_in, states_out) = layouter.assign_region(
            || "hash table",
            |mut region| {
                let mut states_in = Vec::new();
                let mut states_out = Vec::new();
                let hash_helper = Fp::hasher();

                let dummy_input: [Option<&[Fp; 2]>; 1] = [None];
                let dummy_item: [Option<&Fp>; 1] = [None];
                let inputs_i = data
                    .inputs
                    .iter()
                    .map(Some)
                    .chain(dummy_input.into_iter().cycle())
                    .take(self.calcs);
                let controls_i = data
                    .controls
                    .iter()
                    .map(Some)
                    .chain(dummy_item.into_iter().cycle())
                    .take(self.calcs);

                let checks_i = data
                    .checks
                    .iter()
                    .map(|i| i.as_ref())
                    .chain(dummy_item.into_iter().cycle())
                    .take(self.calcs);

                // notice our hash table has a (0, 0, 0) at the beginning
                for col in config.hash_table {
                    region.assign_advice(|| "dummy inputs", col, 0, || Value::known(Fp::ZERO))?;
                }

                for col in config.hash_table_aux {
                    region.assign_advice(
                        || "dummy aux inputs",
                        col,
                        0,
                        || Value::known(Fp::ZERO),
                    )?;
                }

                region.assign_advice(
                    || "control aux head",
                    config.control_aux,
                    0,
                    || Value::known(Fp::ZERO),
                )?;

                let c_ctrl = region.assign_advice(
                    || "control sponge continue head",
                    config.s_sponge_continue,
                    0,
                    || Value::known(Fp::ZERO),
                )?;

                // contraint 0 to zero constant
                region.constrain_equal(c_ctrl.cell(), constants_cell[0].cell())?;

                let mut is_new_sponge = true;
                let mut process_start = 0;
                let mut offset = 1;
                let mut state: [Fp; 3] = [Fp::ZERO; 3];

                for (i, ((inp, control), check)) in
                    inputs_i.zip(controls_i).zip(checks_i).enumerate()
                {
                    let control = control.copied().unwrap_or(Fp::ZERO);
                    offset = i + 1;

                    if is_new_sponge {
                        state[0] = control;
                        process_start = offset;
                    }

                    let inp = inp
                        .map(|[a, b]| [*a, *b])
                        .unwrap_or_else(|| [Fp::ZERO, Fp::ZERO]);

                    state.iter_mut().skip(1).zip(inp).for_each(|(s, inp)| {
                        if is_new_sponge {
                            *s = inp;
                        } else {
                            *s += inp;
                        }
                    });

                    let state_start = state;
                    hash_helper.permute(&mut state); //here we calculate the hash

                    //and sanity check ...
                    if let Some(ck) = check {
                        assert_eq!(*ck, state[0]);
                    }

                    config.s_table.enable(&mut region, offset)?;

                    let c_start = [
                        region.assign_advice(
                            || format!("state input 0_{}", i),
                            config.hash_table_aux[0],
                            offset,
                            || Value::known(state_start[0]),
                        )?,
                        region.assign_advice(
                            || format!("state input 1_{}", i),
                            config.hash_table_aux[1],
                            offset,
                            || Value::known(state_start[1]),
                        )?,
                        region.assign_advice(
                            || format!("state input 2_{}", i),
                            config.hash_table_aux[2],
                            offset,
                            || Value::known(state_start[2]),
                        )?,
                    ];

                    let current_hash = state[0];
                    let c_end = [
                        region.assign_advice(
                            || format!("state output hash_{}", i),
                            config.hash_table_aux[5],
                            offset,
                            || Value::known(state[0]),
                        )?,
                        region.assign_advice(
                            || format!("state output 1_{}", i),
                            config.hash_table_aux[3],
                            offset,
                            || Value::known(state[1]),
                        )?,
                        region.assign_advice(
                            || format!("state output 2_{}", i),
                            config.hash_table_aux[4],
                            offset,
                            || Value::known(state[2]),
                        )?,
                    ];

                    region.assign_advice(
                        || format!("state input control_{}", i),
                        config.hash_table[3],
                        offset,
                        || Value::known(control),
                    )?;

                    region.assign_advice(
                        || format!("state input control_aux_{}", i),
                        config.control_aux,
                        offset,
                        || Value::known(control.invert().unwrap_or(Fp::ZERO)),
                    )?;

                    region.assign_advice(
                        || format!("state continue control_{}", i),
                        config.s_sponge_continue,
                        offset,
                        || Value::known(if is_new_sponge { Fp::ZERO } else { Fp::ONE }),
                    )?;

                    region.assign_advice(
                        || format!("hash input first_{}", i),
                        config.hash_table[1],
                        offset,
                        || Value::known(inp[0]),
                    )?;

                    region.assign_advice(
                        || format!("hash input second_{}", i),
                        config.hash_table[2],
                        offset,
                        || Value::known(inp[1]),
                    )?;

                    is_new_sponge = control <= Fp::from_u128(STEP as u128);

                    //fill all the hash_table[0] with result hash
                    if is_new_sponge {
                        (process_start..offset + 1).try_for_each(|ith| {
                            region
                                .assign_advice(
                                    || format!("hash index_{}", ith),
                                    config.hash_table[0],
                                    ith,
                                    || Value::known(current_hash),
                                )
                                .map(|_| ())
                        })?;
                    }

                    //we directly specify the init state of permutation
                    states_in.push(c_start.map(StateWord::from));
                    states_out.push(c_end.map(StateWord::from));
                }

                // enforce the last row is "not continue", so user can not put a variable
                // message till the last row but this should be acceptable (?)
                let c_last_ctrl = region.assign_advice(
                    || "control sponge continue last",
                    config.s_sponge_continue,
                    offset,
                    || Value::known(Fp::ZERO),
                )?;

                // contraint 0 to tail line
                region.constrain_equal(c_last_ctrl.cell(), constants_cell[0].cell())?;
                Ok((states_in, states_out))
            },
        )?;

        let mut chip_finals = Vec::new();

        for state in states_in {
            let chip = Pow5Chip::construct(config.permute_config.clone());

            let final_state =
                <Pow5Chip<_, 3, 2> as PoseidonInstructions<Fp, Fp::SpecType, 3, 2>>::permute(
                    &chip, layouter, &state,
                )?;

            chip_finals.push(final_state);
        }

        layouter.assign_region(
            || "final state dummy",
            |mut region| {
                for (state, final_state) in states_out.iter().zip(chip_finals.iter()) {
                    for (s_cell, final_cell) in state.iter().zip(final_state.iter()) {
                        region.constrain_equal(s_cell.cell(), final_cell.cell())?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl<Fp: PrimeField, const STEP: usize> Chip<Fp> for PoseidonHashChip<'_, Fp, STEP> {
    type Config = PoseidonHashConfig<Fp>;
    type Loaded = PoseidonHashTable<Fp>;

    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::ff::Field;
    use halo2_proofs::halo2curves::group::ff::PrimeField;
    use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};

    #[test]
    fn poseidon_hash() {
        let b1: Fr = Fr::from_str_vartime("1").unwrap();
        let b2: Fr = Fr::from_str_vartime("2").unwrap();

        let h = Fr::hash([b1, b2]);
        assert_eq!(
            format!("{:?}", h),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a" // "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
    }

    #[test]
    fn poseidon_hash_bytes() {
        let msg = vec![
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
            Fr::from_str_vartime("50331648").unwrap(), //0x3000000
        ];

        let supposed_bytes = 45u64;

        let h = Fr::hash_msg(&msg, Some(supposed_bytes));
        assert_eq!(
            format!("{:?}", h),
            "0x212b546f9c67c4fdcba131035644aa1d8baa8943f84b0a27e8f65b5bd532213e"
        );

        let msg = vec![
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
            Fr::from_str_vartime("3").unwrap(),
            Fr::ZERO,
        ];

        let supposed_bytes = 50u64;

        let h = Fr::hash_msg(&msg, Some(supposed_bytes));
        assert_eq!(
            format!("{:?}", h),
            "0x066397f309d55f6caf6419cbb4120f5ada8e54254061b4b448359de388ab5526"
        );
    }

    use halo2_proofs::dev::MockProver;
    const TEST_STEP: usize = 32;

    // test circuit derived from table data
    impl<Fp: Hashable> Circuit<Fp> for PoseidonHashTable<Fp> {
        type Config = (PoseidonHashConfig<Fp>, usize);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                ..Default::default()
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let hash_tbl = [0; 4].map(|_| meta.advice_column());
            (
                PoseidonHashConfig::configure_sub(meta, hash_tbl, TEST_STEP),
                4,
            )
        }

        fn synthesize(
            &self,
            (config, max_rows): Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = PoseidonHashChip::<Fp, TEST_STEP>::construct(config, self, max_rows);
            chip.load(&mut layouter)
        }
    }

    #[cfg(feature = "print_layout")]
    #[test]
    fn print_circuit() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("layouts/hash-layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Hash circuit Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = HashCircuit {
            calcs: 2,
            ..Default::default()
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_equality_constraints(true)
            .render(7, &circuit, &root)
            .unwrap();
    }

    #[test]
    fn poseidon_hash_circuit() {
        let message1 = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];

        let message2 = [
            Fr::from_str_vartime("2").unwrap(),
            Fr::from_str_vartime("3").unwrap(),
        ];

        let k = 8;
        let circuit = PoseidonHashTable {
            inputs: vec![message1, message2],
            ..Default::default()
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn poseidon_var_len_hash_circuit() {
        let message1 = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];

        let message2 = [Fr::from_str_vartime("50331648").unwrap(), Fr::ZERO];

        let k = 8;
        let circuit = PoseidonHashTable {
            inputs: vec![message1, message2],
            controls: vec![Fr::from_u128(45), Fr::from_u128(13)],
            checks: vec![None, Some(Fr::from_str_vartime("15002881182751877599173281392790087382867290792048832034781070831698029191486").unwrap())],
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let circuit = PoseidonHashTable {
            inputs: vec![message1, message2, message1],
            controls: vec![Fr::from_u128(64), Fr::from_u128(32), Fr::ZERO],
            checks: Vec::new(),
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
