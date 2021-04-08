use std::ops::{Add, Mul};

use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use group::prime::{PrimeCurve};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::toolbox::{SchnorrCS, TranscriptProtocol};
use crate::{/*BatchableProof,*/ CompactProof, Transcript};

/// Used to create proofs.
///
/// To use a [`Prover`], first construct one using [`Prover::new()`],
/// supplying a domain separation label, as well as the transcript to
/// operate on.
///
/// Then, allocate and assign secret ([`Prover::allocate_scalar`]) and
/// public ([`Prover::allocate_point`]) variables, and use those
/// variables to define the proof statements.
///
/// Finally, use [`Prover::prove_compact`] or
/// [`Prover::prove_batchable`] to consume the prover and produce a
/// proof.
pub struct Prover<'a, G> where G: Group {
    transcript: &'a mut Transcript,
    scalars: Vec<<G as group::Group>::Scalar>,
    points: Vec<G>,
    point_labels: Vec<&'static [u8]>,
    constraints: Vec<(PointVar, Vec<(ScalarVar, PointVar)>)>,
}

/// A secret variable used during proving.
#[derive(Copy, Clone)]
pub struct ScalarVar(usize);
/// A public variable used during proving.
#[derive(Copy, Clone)]
pub struct PointVar(usize);

impl<'a, 'b, 'c, G> Prover<'a, G> 
    where G: GroupEncoding + Group + PrimeCurve,
        //   <G as GroupEncoding>::Repr: PrimeField,
          <G as Group>::Scalar: Serialize + Deserialize<'static>,
          &'b <G as Group>::Scalar: Mul<&'b <G as Group>::Scalar>,
          <&'b <G as Group>::Scalar as Mul<&'b <G as Group>::Scalar>>::Output: 'b + Add<&'b <G as Group>::Scalar>,
        //   <<&'b <G as Group>::Scalar as Mul<&'b <G as Group>::Scalar>>::Output as Add<&'b <G as Group>::Scalar>>::Output: Group::Scalar,
    {
    /// Construct a new prover.  The `proof_label` disambiguates proof
    /// statements.
    pub fn new(proof_label: &'static [u8], transcript: &'a mut Transcript) -> Self {
        TranscriptProtocol::<G>::domain_sep(transcript, proof_label);
        Prover {
            transcript,
            scalars: Vec::default(),
            points: Vec::default(),
            point_labels: Vec::default(),
            constraints: Vec::default(),
        }
    }

    /// Allocate and assign a secret variable with the given `label`.
    pub fn allocate_scalar(&mut self, label: &'static [u8], assignment: <G as group::Group>::Scalar) -> ScalarVar {
        TranscriptProtocol::<G>::append_scalar_var(self.transcript, label);
        self.scalars.push(assignment);
        ScalarVar(self.scalars.len() - 1)
    }

    /// Allocate and assign a public variable with the given `label`.
    ///
    /// The point is compressed to be appended to the transcript, and
    /// the compressed point is returned to allow reusing the result
    /// of that computation; it can be safely discarded.
    pub fn allocate_point(
        &mut self,
        label: &'static [u8],
        assignment: G,
    ) -> (PointVar, G) {
        self.transcript.append_point_var(label, &assignment);
        self.points.push(assignment);
        self.point_labels.push(label);
        (PointVar(self.points.len() - 1), assignment)
    }

    /// The compact and batchable proofs differ only by which data they store.
    fn prove_impl(self) -> (<G as group::Group>::Scalar, Vec<<G as group::Group>::Scalar>, Vec<G>) {
        // Construct a TranscriptRng
        let mut rng_builder = self.transcript.build_rng();
        for scalar in &self.scalars {
            rng_builder = rng_builder.rekey_with_witness_bytes(b"", scalar.to_repr().as_ref());
        }
        let mut transcript_rng = rng_builder.finalize(&mut thread_rng());

        // Generate a blinding factor for each secret variable
        let blindings = self
            .scalars
            .iter()
            .map(|_| <G as group::Group>::Scalar::random(&mut transcript_rng))
            .collect::<Vec<<G as group::Group>::Scalar>>();

        // Commit to each blinded LHS
        let mut commitments = Vec::with_capacity(self.constraints.len());
        for (lhs_var, rhs_lc) in &self.constraints {
            let mut commitment: G = <G as group::Group>::identity();
            for (sc_var, pt_var) in rhs_lc.iter() {
                commitment += self.points[pt_var.0] * blindings[sc_var.0];
            }
            commitment -= <G as group::Group>::identity();

            let _encoding = self
                .transcript
                .append_blinding_commitment(self.point_labels[lhs_var.0], &G::from(commitment));

            // commitments.push(encoding);
            commitments.push(G::from(commitment));
        }

        // Obtain a scalar challenge and compute responses
        let challenge = TranscriptProtocol::<G>::get_challenge(self.transcript, b"chal");
        let responses = Iterator::zip(self.scalars.iter(), blindings.iter())
            .map(|(s, b)| <G as Group>::Scalar::add(*b, <G as Group>::Scalar::mul(*s, challenge)) ) // ::from(s * challenge + b))
            .collect::<Vec<<G as group::Group>::Scalar>>();

        (challenge, responses, commitments)
    }

    /// Consume this prover to produce a compact proof.
    pub fn prove_compact(self) -> CompactProof<G> {
        let (challenge, responses, _) = self.prove_impl();

        CompactProof {
            challenge,
            responses,
        }
    }

    // /// Consume this prover to produce a batchable proof.
    // pub fn prove_batchable(self) -> BatchableProof<G> {
    //     let (_, responses, commitments) = self.prove_impl();

    //     BatchableProof {
    //         commitments,
    //         responses,
    //     }
    // }
}

impl<'a, G> SchnorrCS for Prover<'a, G> where G: PrimeCurve + Group {
    type ScalarVar = ScalarVar;
    type PointVar = PointVar;

    fn constrain(&mut self, lhs: PointVar, linear_combination: Vec<(ScalarVar, PointVar)>) {
        self.constraints.push((lhs, linear_combination));
    }
}
