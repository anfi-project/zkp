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
extern crate serde;

use sha2::Sha512;

use bls12_381::{Scalar, G1Projective};
use bls12_381::hash_to_curve::{HashToCurve, ExpandMsgXmd};
use group::GroupEncoding;

use zkp::toolbox::{/*batch_verifier::BatchVerifier, */prover::Prover, verifier::Verifier, SchnorrCS};
use zkp::Transcript;

fn dleq_statement<CS: SchnorrCS>(
    cs: &mut CS,
    x: CS::ScalarVar,
    A: CS::PointVar,
    G: CS::PointVar,
    B: CS::PointVar,
    H: CS::PointVar,
) {
    cs.constrain(A, vec![(x, B)]);
    cs.constrain(G, vec![(x, H)]);
}

const DOMAIN: &[u8] = b"DALEK-ZKP-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

#[test]
fn create_and_verify_compact_dleq() {
    let B = G1Projective::generator();
    let H = <G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(
        B.to_bytes(), DOMAIN,
    );
    // let H_aff = G1Affine::from(H);

    let (proof, cmpr_A, cmpr_G) = {
        let x = Scalar::from(89327492234u64);

        let A = B * x;
        let G = H * x;

        let mut transcript = Transcript::new(b"DLEQTest");
        let mut prover = Prover::new(b"DLEQProof", &mut transcript);

        // XXX committing var names to transcript forces ordering (?)
        let var_x = prover.allocate_scalar(b"x", x);
        let (var_B, _) = prover.allocate_point(b"B", B);
        let (var_H, _) = prover.allocate_point(b"H", H);
        let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
        let (var_G, cmpr_G) = prover.allocate_point(b"G", G);

        dleq_statement(&mut prover, var_x, var_A, var_G, var_B, var_H);

        (prover.prove_compact(), cmpr_A, cmpr_G)
    };

    let mut transcript = Transcript::new(b"DLEQTest");
    let mut verifier = Verifier::new(b"DLEQProof", &mut transcript);

    let var_x = verifier.allocate_scalar(b"x");
    let var_B = verifier.allocate_point(b"B", B).unwrap();
    let var_H = verifier.allocate_point(b"H", H).unwrap();
    let var_A = verifier.allocate_point(b"A", cmpr_A).unwrap();
    let var_G = verifier.allocate_point(b"G", cmpr_G).unwrap();

    dleq_statement(&mut verifier, var_x, var_A, var_G, var_B, var_H);

    assert!(verifier.verify_compact(&proof).is_ok());
}

// #[test]
// fn create_and_verify_batchable_dleq() {
//     let B = G1Affine::generator();
//     let H = <G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(
//         B.to_compressed(), DOMAIN,
//     );
//     let H_aff = G1Affine::from(H);

//     let (proof, cmpr_A, cmpr_G) = {
//         let x = Scalar::from(89327492234u64);

//         let A = B * x;
//         let G = H * x;

//         let mut transcript = Transcript::new(b"DLEQTest");
//         let mut prover = Prover::new(b"DLEQProof", &mut transcript);

//         // XXX committing var names to transcript forces ordering (?)
//         let var_x = prover.allocate_scalar(b"x", x);
//         let (var_B, _) = prover.allocate_point(b"B", B);
//         let (var_H, _) = prover.allocate_point(b"H", H_aff);
//         let (var_A, cmpr_A) = prover.allocate_point(b"A", G1Affine::from(A));
//         let (var_G, cmpr_G) = prover.allocate_point(b"G", G1Affine::from(G));

//         dleq_statement(&mut prover, var_x, var_A, var_G, var_B, var_H);

//         (prover.prove_batchable(), cmpr_A, cmpr_G)
//     };

//     let mut transcript = Transcript::new(b"DLEQTest");
//     let mut verifier = Verifier::new(b"DLEQProof", &mut transcript);

//     let var_x = verifier.allocate_scalar(b"x");
//     let var_B = verifier.allocate_point(b"B", B).unwrap();
//     let var_H = verifier.allocate_point(b"H", H_aff).unwrap();
//     let var_A = verifier.allocate_point(b"A", cmpr_A).unwrap();
//     let var_G = verifier.allocate_point(b"G", cmpr_G).unwrap();

//     dleq_statement(&mut verifier, var_x, var_A, var_G, var_B, var_H);

//     assert!(verifier.verify_batchable(&proof).is_ok());
// }

// #[test]
// fn create_and_batch_verify_batchable_dleq() {
//     let B = G1Affine::generator();
//     let H = <G1Projective as HashToCurve<ExpandMsgXmd<Sha512>>>::hash_to_curve(
//         B.to_compressed(), DOMAIN,
//     );
//     let H_aff = G1Affine::from(H);

//     let batch_size = 16;

//     let mut proofs = Vec::new();
//     let mut cmpr_As = Vec::new();
//     let mut cmpr_Gs = Vec::new();

//     for j in 0..batch_size {
//         let (proof, cmpr_A, cmpr_G) = {
//             let x = Scalar::from((j as u64) + 89327492234u64);

//             let A = B * x;
//             let G = H * x;

//             let mut transcript = Transcript::new(b"DLEQBatchTest");
//             let mut prover = Prover::new(b"DLEQProof", &mut transcript);

//             // XXX committing var names to transcript forces ordering (?)
//             let var_x = prover.allocate_scalar(b"x", x);
//             let (var_B, _) = prover.allocate_point(b"B", B);
//             let (var_H, _) = prover.allocate_point(b"H", H_aff);
//             let (var_A, cmpr_A) = prover.allocate_point(b"A", G1Affine::from(A));
//             let (var_G, cmpr_G) = prover.allocate_point(b"G", G1Affine::from(G));

//             dleq_statement(&mut prover, var_x, var_A, var_G, var_B, var_H);

//             (prover.prove_batchable(), cmpr_A, cmpr_G)
//         };
//         proofs.push(proof);
//         cmpr_As.push(cmpr_A);
//         cmpr_Gs.push(cmpr_G);
//     }

//     let mut transcripts = vec![Transcript::new(b"DLEQBatchTest"); batch_size];
//     let transcript_refs = transcripts.iter_mut().collect();
//     let mut verifier = BatchVerifier::new(b"DLEQProof", batch_size, transcript_refs).unwrap();

//     let var_x = verifier.allocate_scalar(b"x");
//     let var_B = verifier.allocate_static_point(b"B", B).unwrap();
//     let var_H = verifier.allocate_static_point(b"H", H_aff).unwrap();
//     let var_A = verifier.allocate_instance_point(b"A", cmpr_As).unwrap();
//     let var_G = verifier.allocate_instance_point(b"G", cmpr_Gs).unwrap();

//     dleq_statement(&mut verifier, var_x, var_A, var_G, var_B, var_H);

//     assert!(verifier.verify_batchable(&proofs).is_ok());
// }
