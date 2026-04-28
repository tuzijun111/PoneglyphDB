//! Generic IPA commitment prototype for every dataset in `src/data`.
//!
//! `ezkl`'s cheap-commitment path uses unblinded advice columns. The current
//! `multijoin` dependency on `halo2_PSE` does not expose that API, so the
//! closest working analogue in this repository is to commit each dataset
//! through fixed columns. Those commitments are still cheap IPA commitments,
//! but they live in the verifying key instead of the proof transcript.
//!
//! This file does two things:
//! 1. It computes standalone IPA commitments to canonicalized dataset columns.
//! 2. It shows how to verify those commitments inside a PLONKish circuit by
//!    looking up a public row against the committed fixed-column table.
//!
//! The in-circuit verification pattern is the `lookup_any` gate below. The
//! external commitment check is the comparison between standalone IPA
//! commitments and the fixed commitments that appear in the verifying key.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::{
        group::Curve,
        pasta::{vesta, EqAffine, Fp},
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, Selector,
    },
    poly::{
        commitment::{Blind, Params, ParamsProver},
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
            strategy::SingleStrategy,
        },
        EvaluationDomain, Rotation, VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
};

// Every dataset row is padded/truncated into this many field slots so one
// generic circuit configuration can handle all tables in `src/data`.
const MAX_COLUMNS: usize = 16;
// Extra rows reserved beyond the real dataset length so fixed/advice layout has
// room for Halo2's unusable rows and some safety margin.
const LOGROWS_HEADROOM: usize = 32;
const PROOF_DATASET_BASENAME: &str = "nation.tbl";

#[derive(Clone, Debug)]
struct DatabaseCommitConfig {
    // Enables the single-row lookup proving that the queried row belongs to the
    // committed fixed-column table.
    q_lookup: Selector,
    // Advice columns that carry the row being proven inside the circuit.
    witness_cols: Vec<Column<Advice>>,
    // Fixed columns that hold the committed dataset itself.
    table_cols: Vec<Column<Fixed>>,
    // Public inputs expose the queried row so the verifier sees exactly which
    // row membership is being proven.
    instance: Column<Instance>,
}

#[derive(Clone, Debug)]
struct DatabaseCommitCircuit {
    // Only used in region labels and panic messages to make test output legible.
    dataset_name: String,
    // Canonicalized table contents that will be loaded into fixed columns.
    committed_rows: Vec<Vec<Fp>>,
    // Canonicalized public row whose membership is checked with a lookup.
    membership_row: Vec<Fp>,
}

#[derive(Clone, Debug)]
struct DatasetRecord {
    name: String,
    // Retained for diagnostics so failing tests can point back to the source file.
    path: PathBuf,
    // Original row width before padding to `MAX_COLUMNS`.
    width: usize,
    // Smallest power-of-two row count that fits this dataset plus headroom.
    logrows: u32,
    // Canonicalized rows ready to drop into the circuit / standalone commitment.
    rows: Vec<Vec<Fp>>,
    // A concrete row taken from the dataset and used as the membership witness.
    membership_row: Vec<Fp>,
}

impl Circuit<Fp> for DatabaseCommitCircuit {
    type Config = DatabaseCommitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            dataset_name: self.dataset_name.clone(),
            committed_rows: self.committed_rows.clone(),
            membership_row: vec![Fp::from(0); MAX_COLUMNS],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let q_lookup = meta.complex_selector();
        // We allocate the maximum width up front so one circuit shape can be
        // reused for all datasets, even though many tables use fewer columns.
        let witness_cols = (0..MAX_COLUMNS)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>();
        let table_cols = (0..MAX_COLUMNS)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>();
        let instance = meta.instance_column();

        for &col in &witness_cols {
            meta.enable_equality(col);
        }
        meta.enable_equality(instance);

        // When `q_lookup` is enabled on a row, each witness cell must match the
        // corresponding fixed-column entry on some row of the committed table.
        meta.lookup_any("dataset row membership", |meta| {
            let q = meta.query_selector(q_lookup);

            witness_cols
                .iter()
                .zip(table_cols.iter())
                .map(|(&witness_col, &table_col)| {
                    (
                        q.clone() * meta.query_advice(witness_col, Rotation::cur()),
                        meta.query_fixed(table_col, Rotation::cur()),
                    )
                })
                .collect::<Vec<_>>()
        });

        DatabaseCommitConfig {
            q_lookup,
            witness_cols,
            table_cols,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Load the committed dataset into fixed columns. In this fallback design
        // the resulting IPA commitments live in the verifying key.
        layouter.assign_region(
            || format!("load {} into fixed columns", self.dataset_name),
            |mut region| {
                for (row, dataset_row) in self.committed_rows.iter().enumerate() {
                    for (idx, value) in dataset_row.iter().enumerate() {
                        region.assign_fixed(
                            || "dataset table",
                            config.table_cols[idx],
                            row,
                            || Value::known(*value),
                        )?;
                    }
                }

                Ok(())
            },
        )?;

        // Assign a single queried row into advice columns and enable the lookup
        // gate so the circuit proves this row appears in the committed table.
        let witness_cells = layouter.assign_region(
            || format!("prove one public row is in {}", self.dataset_name),
            |mut region| {
                config.q_lookup.enable(&mut region, 0)?;

                config
                    .witness_cols
                    .iter()
                    .enumerate()
                    .map(|(idx, &col)| {
                        region.assign_advice(
                            || "membership witness",
                            col,
                            0,
                            || Value::known(self.membership_row[idx]),
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<Fp, Fp>>, Error>>()
            },
        )?;

        // Expose the queried row as public inputs. This makes the membership
        // claim explicit to the verifier.
        for (row, cell) in witness_cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, row)?;
        }

        Ok(())
    }
}

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("data")
}

// Enumerate the tabular datasets we want to commit to. Code files in this
// directory are intentionally excluded.
fn dataset_file_paths() -> Vec<PathBuf> {
    let mut paths = fs::read_dir(data_dir())
        .expect("failed to list src/data")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("tbl") | Some("cvs")
            )
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

// Pick the smallest `k` such that `2^k` comfortably fits the dataset rows plus
// some reserve rows for the proving system.
fn minimum_logrows(num_rows: usize) -> u32 {
    let required_rows = num_rows + LOGROWS_HEADROOM;
    let mut k = 4u32;

    while (1usize << k) < required_rows {
        k += 1;
    }

    k
}

// TPC-H `.tbl` and the local `region.cvs` file are pipe-delimited and usually
// end each row with a trailing `|`. Dropping trailing empty cells gives a stable
// logical row width.
fn normalize_fields(line: &str) -> Vec<&str> {
    let mut fields = line.split('|').map(str::trim).collect::<Vec<_>>();
    while fields.last().map_or(false, |last| last.is_empty()) {
        fields.pop();
    }
    fields
}

// Stable string encoding for non-numeric cells. It only needs to be
// deterministic here; cryptographic collision resistance is not the goal.
fn hash_string_to_u64(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// Signed integers / scaled floats are mapped into `u64` with zigzag encoding so
// small negative values remain compact and deterministic.
fn zigzag_i128(value: i128) -> u64 {
    ((value << 1) ^ (value >> 127)) as u64
}

// Canonical per-cell encoding used before turning rows into field elements.
// The rule is:
// - `u64` stays as-is
// - signed ints become zigzag-encoded
// - floats are scaled by 1000 then zigzag-encoded
// - everything else is hashed as text
fn encode_cell_to_u64(cell: &str) -> u64 {
    let trimmed = cell.trim();

    if trimmed.is_empty() {
        return 0;
    }

    if let Ok(value) = trimmed.parse::<u64>() {
        return value;
    }

    if let Ok(value) = trimmed.parse::<i64>() {
        return zigzag_i128(value as i128);
    }

    if let Ok(value) = trimmed.parse::<f64>() {
        let scaled = (value * 1000.0).round() as i128;
        return zigzag_i128(scaled);
    }

    hash_string_to_u64(trimmed)
}

// Convert one logical row into the fixed-width representation used everywhere
// else in this file. Unused trailing columns are padded with zero.
fn encode_dataset_row(fields: &[&str]) -> Vec<Fp> {
    assert!(
        fields.len() <= MAX_COLUMNS,
        "dataset row has width {} but MAX_COLUMNS is {}",
        fields.len(),
        MAX_COLUMNS
    );

    let mut row = vec![Fp::from(0); MAX_COLUMNS];
    for (idx, field) in fields.iter().enumerate() {
        row[idx] = Fp::from(encode_cell_to_u64(field));
    }
    row
}

// Read one dataset file, canonicalize every row, and record the first row as a
// concrete membership witness for the tests below.
fn load_dataset(path: &Path) -> io::Result<DatasetRecord> {
    let reader = BufReader::new(File::open(path)?);
    let mut rows = Vec::new();
    let mut width = 0usize;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let fields = normalize_fields(&line);
        width = width.max(fields.len());
        rows.push(encode_dataset_row(&fields));
    }

    assert!(
        !rows.is_empty(),
        "dataset {} should contain at least one row",
        path.display()
    );

    Ok(DatasetRecord {
        name: path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("dataset filename should be valid UTF-8")
            .to_string(),
        path: path.to_path_buf(),
        width,
        logrows: minimum_logrows(rows.len()),
        // Using the first row keeps the witness selection deterministic.
        membership_row: rows[0].clone(),
        rows,
    })
}

// Load every dataset once so the tests can iterate uniformly over the data
// directory.
fn load_all_datasets() -> Vec<DatasetRecord> {
    dataset_file_paths()
        .into_iter()
        .map(|path| {
            load_dataset(&path)
                .unwrap_or_else(|err| panic!("failed to load {}: {err}", path.display()))
        })
        .collect()
}

// Transpose row-major data into column-major form because IPA commitments are
// taken one column polynomial at a time.
fn committed_columns(rows: &[Vec<Fp>]) -> Vec<Vec<Fp>> {
    let mut cols = vec![Vec::with_capacity(rows.len()); MAX_COLUMNS];

    for row in rows {
        for (idx, value) in row.iter().enumerate() {
            cols[idx].push(*value);
        }
    }

    cols
}

// Standalone commitment helper: build the evaluation vector for one column and
// commit to it directly with IPA. We later compare these points with the VK's
// fixed commitments.
fn lagrange_commit(params: &ParamsIPA<vesta::Affine>, column: &[Fp], logrows: u32) -> EqAffine {
    let domain: EvaluationDomain<Fp> = EvaluationDomain::new(1, logrows);
    let mut poly = domain.empty_lagrange();

    for (row, value) in column.iter().enumerate() {
        poly[row] = *value;
    }

    params.commit_lagrange(&poly, Blind::default()).to_affine()
}

// Cheap sanity check for a dataset: does the lookup-based membership gadget
// accept a real row from the table?
fn run_membership_mock(dataset: &DatasetRecord) {
    let circuit = DatabaseCommitCircuit {
        dataset_name: dataset.name.clone(),
        committed_rows: dataset.rows.clone(),
        membership_row: dataset.membership_row.clone(),
    };

    let mock = MockProver::run(
        dataset.logrows,
        &circuit,
        vec![dataset.membership_row.clone()],
    )
    .unwrap_or_else(|err| panic!("mock prover setup failed for {}: {err:?}", dataset.name));
    assert_eq!(
        mock.verify(),
        Ok(()),
        "membership lookup constraints failed for {}",
        dataset.name
    );
}

// Full end-to-end path for one dataset:
// 1. commit the fixed columns through key generation,
// 2. compare those commitments to standalone IPA commitments,
// 3. generate a proof, and
// 4. verify the proof.
fn run_end_to_end_proof(dataset: &DatasetRecord) {
    let circuit = DatabaseCommitCircuit {
        dataset_name: dataset.name.clone(),
        committed_rows: dataset.rows.clone(),
        membership_row: dataset.membership_row.clone(),
    };

    let params = ParamsIPA::<vesta::Affine>::new(dataset.logrows);
    let vk = keygen_vk(&params, &circuit)
        .unwrap_or_else(|err| panic!("keygen_vk failed for {}: {err:?}", dataset.name));

    let expected_commitments = committed_columns(&dataset.rows)
        .iter()
        .map(|column| lagrange_commit(&params, column, dataset.logrows))
        .collect::<Vec<_>>();
    assert_eq!(
        &vk.fixed_commitments()[..expected_commitments.len()],
        expected_commitments.as_slice(),
        "fixed-column commitments did not match standalone IPA commitments for {}",
        dataset.name
    );

    let pk = keygen_pk(&params, vk, &circuit)
        .unwrap_or_else(|err| panic!("keygen_pk failed for {}: {err:?}", dataset.name));

    let mut rng = OsRng;
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[dataset.membership_row.as_slice()]],
        &mut rng,
        &mut transcript,
    )
    .unwrap_or_else(|err| panic!("proof generation failed for {}: {err:?}", dataset.name));
    let proof = transcript.finalize();

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(
        verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[dataset.membership_row.as_slice()]],
            &mut transcript,
        )
        .is_ok(),
        "proof verification failed for {}",
        dataset.name
    );
}

#[test]
// Fast coverage pass over every dataset file. This is the part that shows the
// PLONKish in-circuit verification pattern working generically.
fn database_commitment_membership_constraints_work_for_all_datasets() {
    for dataset in load_all_datasets() {
        assert!(
            dataset.width <= MAX_COLUMNS,
            "dataset {} at {} exceeds MAX_COLUMNS={}",
            dataset.name,
            dataset.path.display(),
            MAX_COLUMNS
        );
        run_membership_mock(&dataset);
    }
}

#[test]
// One fully exercised proof roundtrip kept small enough to run by default.
fn database_commitment_proof_roundtrip_for_nation_tbl() {
    let dataset = load_dataset(&data_dir().join(PROOF_DATASET_BASENAME))
        .expect("failed to load the proof-roundtrip dataset");

    run_membership_mock(&dataset);
    run_end_to_end_proof(&dataset);
}

#[test]
#[ignore = "heavy: keygen on every dataset in src/data"]
// Optional exhaustive proof test. Useful when you want every dataset to go
// through the full IPA commitment / VK comparison / proof verification path.
fn database_commitment_vk_matches_standalone_ipa_for_all_datasets() {
    for dataset in load_all_datasets() {
        run_end_to_end_proof(&dataset);
    }
}
