use log::debug;
use prompt::{puzzle, welcome};
use semaphore::{
    air::rescue::{apply_inv_mds, ARK1, ARK2},
    print_trace,
    prover::{apply_rescue_round, SemaphoreProver},
    AccessSet, PrivKey, PubKey, Signal,
};
use std::{io::Write, time::Instant};
use winter_utils::Serializable;

use winterfell::{
    crypto::{hashers::Rp64_256 as Rescue, Hasher, MerkleTree},
    math::{fields::f64::BaseElement as Felt, FieldElement},
    Prover, TraceTable,
};

// DATA
// ================================================================================================

/// Public keys of users in the access set.
const PUB_KEYS: [&str; 8] = [
    "04f6d8d05f52012c0a705c1e0dcb1ff64ba0842c8c14f1f0f18e95254bdcfbea",
    "af84cf58cb71709c5a94750e69f9cbad0244d6c8e437f4e822c58f0c45c69ea0",
    "964650c5645e30b1ff74574a6fc4cdb78eaa1be3dfd43f01050b1b0e41d4db36",
    "d5a494b415c20d7d00fbace4f725b596da7c646d80e622956d7f09eebc93fef9",
    "9d7083734388833056ae25382dbcfb39b6a1ee78a6d63f136d83400569adc319",
    "a7ae57a7b2c60871e86d152e9e712ab5a3630f6183a7c1d07ba4429fead88018",
    "1995c40e8e46a009b0d61d89634f3c959d13322ef3a84b410a811eb4fc06d08b",
    "cf855bce16bb7b37f874324da9f72dd0d0e6f6e9f9e29100f66c7b57c6895ef5",
];

/// Our private key; this key corresponds to the 4th public key above (d5a494b415c2...).
// const MY_PRIV_KEY: &str = "86475af21e4445b71bfa496416ee2d0765946bd3a854a77fe07db53c7994d0a5";

/// A topic on which we'll send a signal
const TOPIC: &str = "The Winter is Coming...";

// SEMAPHORE TESTER
// ================================================================================================

pub fn forge_signal() -> Signal {
    // Target the first public key
    let pub_keys = PUB_KEYS
        .iter()
        .map(|&k| PubKey::parse(k))
        .collect::<Vec<_>>();
    let first_pubkey = pub_keys[0].elements();
    let mut rescue_state = [
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        first_pubkey[0],
        first_pubkey[1],
        first_pubkey[2],
        first_pubkey[3],
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];

    // Reverse Rp64_256 algorithm
    for round in (0..7).rev() {
        // Reverse add_constants
        rescue_state
            .iter_mut()
            .enumerate()
            .for_each(|(i, s)| *s -= ARK2[round][i]);
        // Reverse apply_mds
        apply_inv_mds(&mut rescue_state);
        // Reverse apply_inv_sbox
        rescue_state.iter_mut().for_each(|s| *s = s.exp(7));
        // Reverse add_constants
        rescue_state
            .iter_mut()
            .enumerate()
            .for_each(|(i, s)| *s -= ARK1[round][i]);
        // Reverse apply_mds
        apply_inv_mds(&mut rescue_state);
        // Reverse apply_sbox
        rescue_state
            .iter_mut()
            .for_each(|s| *s = s.exp(10540996611094048183));
    }

    // Initialize a trace with 25 columns and 32 lines
    let mut trace = TraceTable::new(25, 32);

    // Copy the fake initial Rescue state
    let mut trace_state = [Felt::ZERO; 25];
    trace_state[..12].clone_from_slice(&rescue_state[..12]);

    // Initialize the nullifier computation
    let topic_hash: [Felt; 4] = Rescue::hash(TOPIC.as_bytes()).into();
    trace_state[12] = Felt::new(8);
    trace_state[16..20].clone_from_slice(&rescue_state[4..8]);
    trace_state[20..24].clone_from_slice(&topic_hash);
    trace.update_row(0, &trace_state);

    // Compute the nullifier
    for round in 0..7 {
        apply_rescue_round(&mut trace_state[..12], round);
        apply_rescue_round(&mut trace_state[12..24], round);
        trace.update_row(round + 1, &trace_state);
    }

    // Save the computed nullifier, which is: 05321040103b38da154baabbf2e7e56efb562d4dbdfeb30c058f17a25e5e2c4b
    let nullifier = <Rescue as Hasher>::Digest::from([
        trace_state[16],
        trace_state[17],
        trace_state[18],
        trace_state[19],
    ]);

    // Compute the Merkle tree for the public keys
    let leaves = pub_keys
        .iter()
        .map(|p| <Rescue as Hasher>::Digest::new(p.elements()))
        .collect::<Vec<_>>();
    assert_eq!(leaves.len(), 8);
    let key_tree: MerkleTree<Rescue> = MerkleTree::new(leaves).unwrap();
    let merkle_path = key_tree.prove(0).unwrap();
    assert_eq!(merkle_path.len(), 4);
    assert_eq!(<[Felt; 4]>::from(merkle_path[0]), first_pubkey);

    // Fill the trace
    for cycle_num in 1..4 {
        trace_state[0] = Felt::new(8);
        trace_state[1] = Felt::ZERO;
        trace_state[2] = Felt::ZERO;
        trace_state[3] = Felt::ZERO;
        let path_node: [Felt; 4] = merkle_path[cycle_num].into();
        path_node
            .iter()
            .enumerate()
            .for_each(|(i, v)| trace_state[8 + i] = *v);
        for i in 12..25 {
            trace_state[i] = Felt::ZERO;
        }
        trace_state[16] = trace_state[4];
        trace_state[17] = trace_state[5];
        trace_state[18] = trace_state[6];
        trace_state[19] = trace_state[7];
        trace.update_row(8 * cycle_num, &trace_state);

        for round in 0..7 {
            apply_rescue_round(&mut trace_state[..12], round);
            apply_rescue_round(&mut trace_state[12..24], round);
            trace.update_row(8 * cycle_num + round + 1, &trace_state);
        }
    }

    // Set a bit to one to ensure the constraint degree is not zero, without
    // actually changing the validity of the execution trace.
    // Otherwise, running in debug mode fails.
    trace.set(24, 1, FieldElement::ONE);

    // Display the generated trace
    print_trace(&trace, 1, 0, 0..25);

    // Generate a proof
    let prover = SemaphoreProver::default();
    let proof = prover.prove(trace).expect("failed to generate proof");
    Signal { nullifier, proof }
}

pub fn main() {
    // configure logging
    env_logger::Builder::new()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(log::LevelFilter::Debug)
        .init();

    welcome();
    puzzle(PUZZLE_DESCRIPTION);

    // build an access set from public keys
    let access_set = AccessSet::new(
        PUB_KEYS
            .iter()
            .map(|&k| PubKey::parse(k))
            .collect::<Vec<_>>(),
    );

    // parse our private key... which is not necessary when forging a signal
    // let my_key = PrivKey::parse(MY_PRIV_KEY);

    debug!("============================================================");

    // create a signal using this private key on some topic; this also includes building a STARK
    // proof attesting that the private key is in the access set, and that the nullifier contained
    // in the signal was built correctly.
    let now = Instant::now();

    // Forge a signal without using the private key
    // let signal = access_set.make_signal(&my_key, TOPIC);
    let signal = forge_signal();
    debug!(
        "---------------------\nSignal created in {} ms",
        now.elapsed().as_millis()
    );

    // print out some stats about the proof
    debug!("{}", signal);
    debug!("---------------------");

    // the signal should be valid against this topic
    let now = Instant::now();
    match access_set.verify_signal(TOPIC, signal.clone()) {
        Ok(_) => debug!(
            "Signal verified in {:.1} ms",
            now.elapsed().as_micros() as f64 / 1000f64
        ),
        Err(err) => debug!("something went terribly wrong: {}", err),
    }
    debug!("============================================================");

    // Modified nullifier is: aac9702c5dbb348dcc1456d236b26ff08a05bedf5278639a1a6719478949c0f1

    assert_ne!(
        signal.nullifier.to_bytes(),
        hex::decode("fa9f5e2287b26f5fc91643a65ecfebbf308c6230283cd5c2a6a57ffe8a60e19d").unwrap()
    );
}

// PUZZLE DESCRIPTION
// ================================================================================================

const PUZZLE_DESCRIPTION: &str = "\
Alice implemented a Semaphore protocol to collect anonymous votes from her friends on various
topics. She collected public keys from 7 of her friends, and together with her public key, built
an access set out of them.

During one of the votes, Alice collected 9 valid signals on the same topic. But that should not be
possible! The semaphore protocol guarantees that every user can vote only once on a given topic.
Someone must have figured out how to create multiple signals on the same topic.

Below is a transcript for generating a valid signal on a topic using your private key. Can you
figure out how to create a valid signal with a different nullifier on the same topic?
";