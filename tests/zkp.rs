// -*- coding: utf-8; mode: rust; -*-
//
// To the extent possible under law, the authors have waived all
// copyright and related or neighboring rights to zkp,
// using the Creative Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/1.0/> for full
// details.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>
#![allow(non_snake_case)]

extern crate bincode;
extern crate bls12_381;
extern crate serde;
extern crate sha2;
#[macro_use]
extern crate zkp;

use self::sha2::Sha512;

use bls12_381::{Scalar, G1Affine, G1Projective};
use bls12_381::hash_to_curve::{HashToCurve, ExpandMsgXmd};

use zkp::Transcript;

const DOMAIN: &[u8] = b"DALEK-ZKP-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

define_proof! {dleq, "DLEQ Example Proof", (x), (A, B, H), (G) : A = (x * G), B = (x * H) }

#[test]
fn create_and_verify_compact() {
    let G = G1Affine::generator();

    // Prover's scope
    let (proof, points) = {
        let H = <G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(
            b"A VRF input, for instance", DOMAIN,
        );
        let H_aff = G1Affine::from(H);
        let x = Scalar::from(89327492234u64).invert().unwrap();
        let A = G1Affine::from(G1Affine::generator() * x);
        let B = G1Affine::from(H * x);

        let mut transcript = Transcript::new(b"DLEQTest");
        dleq::prove_compact(
            &mut transcript,
            dleq::ProveAssignments {
                x: &x,
                A: &A,
                B: &B,
                G: &G,
                H: &H_aff,
            },
        )
    };

    // Serialize and parse bincode representation
    let proof_bytes = bincode::serialize(&proof).unwrap();
    let parsed_proof: dleq::CompactProof = bincode::deserialize(&proof_bytes).unwrap();

    // Verifier logic
    let mut transcript = Transcript::new(b"DLEQTest");
    assert!(dleq::verify_compact(
        &parsed_proof,
        &mut transcript,
        dleq::VerifyAssignments {
            A: &points.A,
            B: &points.B,
            G: &G,
            H: &G1Affine::from(<G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(
                b"A VRF input, for instance", DOMAIN,
            )),
        },
    )
    .is_ok());
}

#[test]
fn create_and_verify_batchable() {
    // identical to above but with batchable proofs
    let G = G1Affine::generator();

    // Prover's scope
    let (proof, points) = {
        let H = <G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(
            b"A VRF input, for instance", DOMAIN,
        );
        let H_aff = G1Affine::from(H);
        let x = Scalar::from(89327492234u64).invert().unwrap();
        let A = G1Affine::from(&G * &x);
        let B = G1Affine::from(&H * &x);

        let mut transcript = Transcript::new(b"DLEQTest");
        dleq::prove_batchable(
            &mut transcript,
            dleq::ProveAssignments {
                x: &x,
                A: &A,
                B: &B,
                G: &G,
                H: &H_aff,
            },
        )
    };

    // Serialize and parse bincode representation
    let proof_bytes = bincode::serialize(&proof).unwrap();
    let parsed_proof: dleq::BatchableProof = bincode::deserialize(&proof_bytes).unwrap();

    // Verifier logic
    let mut transcript = Transcript::new(b"DLEQTest");
    assert!(dleq::verify_batchable(
        &parsed_proof,
        &mut transcript,
        dleq::VerifyAssignments {
            A: &points.A,
            B: &points.B,
            G: &G,
            H: &G1Affine::from(<G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(
                b"A VRF input, for instance", DOMAIN,
            )),
        },
    )
    .is_ok());
}

#[test]
fn create_batch_and_batch_verify() {
    let messages = [
        "One message",
        "Another message",
        "A third message",
        "A fourth message",
    ];

    let G = G1Affine::generator();

    // Prover's scope
    let (proofs, pubkeys, vrf_outputs) = {
        let mut proofs = vec![];
        let mut pubkeys = vec![];
        let mut vrf_outputs = vec![];

        for (i, message) in messages.iter().enumerate() {
            let H = G1Affine::from(<G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(
                message.as_bytes(), DOMAIN,
            ));
            let H_aff = G1Affine::from(H);
            let x = Scalar::from(89327492234u64) * Scalar::from((i + 1) as u64);
            let A = G1Affine::from(&G * &x);
            let B = G1Affine::from(&H * &x);

            let mut transcript = Transcript::new(b"DLEQTest");
            let (proof, points) = dleq::prove_batchable(
                &mut transcript,
                dleq::ProveAssignments {
                    x: &x,
                    A: &A,
                    B: &B,
                    G: &G,
                    H: &H_aff,
                },
            );

            proofs.push(proof);
            pubkeys.push(points.A);
            vrf_outputs.push(points.B);
        }

        (proofs, pubkeys, vrf_outputs)
    };

    // Verifier logic
    let mut transcripts = vec![Transcript::new(b"DLEQTest"); messages.len()];

    assert!(dleq::batch_verify(
        &proofs,
        transcripts.iter_mut().collect(),
        dleq::BatchVerifyAssignments {
            A: pubkeys,
            B: vrf_outputs,
            H: messages
                .iter()
                .map(
                    |message| G1Affine::from(<G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(
                        message.as_bytes(), DOMAIN,
                    ))
                )
                .collect(),
            G: G,
        },
    )
    .is_ok());
}
