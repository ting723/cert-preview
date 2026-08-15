//! Certificate chain reconstruction.
//!
//! Linking is by issuer/subject name equality, reinforced by
//! Authority Key Identifier / Subject Key Identifier when both ends carry
//! them. We never claim cryptographic validity — `complete` means "the names
//! line up all the way to a self-issued certificate".

use std::collections::{HashMap, HashSet};

use crate::model::{Bundle, ChainSummary, Diagnostic};

/// Reconstruct every chain present in `bundle`.
///
/// Chains are grown from leaves (certificates that are not the issuer of any
/// other certificate in the bundle) upward to a self-issued root. The result
/// is independent of the order the certificates appeared in the input, which
/// is why `chain-shuffled.pem` links identically to `chain.pem`.
pub fn link(bundle: &Bundle) -> Vec<ChainSummary> {
    let certs: Vec<(usize, &crate::model::CertificateInfo)> = bundle.certificates().collect();
    if certs.is_empty() {
        return Vec::new();
    }

    // Subject name -> item index. The last certificate with a given subject
    // wins; subjects are unique in any well-formed bundle.
    let by_subject: HashMap<&str, usize> =
        certs.iter().map(|(i, c)| (c.subject.rfc4514.as_str(), *i)).collect();

    let parent_of = |issuer: &str| -> Option<usize> { by_subject.get(issuer).copied() };

    let mut chains = Vec::new();
    for (i, leaf) in &certs {
        // Skip non-leaves: a chain always starts from a descendant, so the
        // leaf that begins it is the one that is nobody's issuer.
        let is_issuer_of_another = certs.iter().any(|(j, other)| {
            *j != *i && other.issuer.rfc4514 == leaf.subject.rfc4514
        });
        if is_issuer_of_another {
            continue;
        }

        let mut indices: Vec<u32> = Vec::new();
        let mut diagnostics = Vec::new();
        let mut visited = HashSet::new();
        let mut cur = Some(*i);
        let mut complete = false;
        let mut self_signed_only = false;

        while let Some(ci) = cur {
            if !visited.insert(ci) {
                diagnostics.push(Diagnostic::error(
                    "CHAIN_CYCLE",
                    "issuer links form a loop; chain building stopped",
                ));
                break;
            }
            indices.push(ci as u32);

            let cert = certs
                .iter()
                .find(|(j, _)| *j == ci)
                .map(|(_, c)| *c)
                .expect("index came from the same certificate list");

            // A self-issued certificate terminates the chain.
            if cert.self_issued {
                complete = true;
                self_signed_only = indices.len() == 1;
                break;
            }

            match parent_of(&cert.issuer.rfc4514) {
                Some(p) if p != ci => {
                    // Optionally reinforce with key identifiers when present:
                    // the child's authorityKeyIdentifier must equal the
                    // parent's subjectKeyIdentifier.
                    let parent_cert = certs
                        .iter()
                        .find(|(j, _)| *j == p)
                        .map(|(_, c)| *c)
                        .expect("index came from the same certificate list");
                    if let (Some(akid), Some(skid)) = (
                        &cert.extensions.authority_key_id,
                        &parent_cert.extensions.subject_key_id,
                    ) {
                        if akid != skid {
                            diagnostics.push(Diagnostic::warn(
                                "KEY_ID_MISMATCH",
                                "authorityKeyIdentifier does not match the parent's subjectKeyIdentifier",
                            ));
                        }
                    }
                    cur = Some(p);
                }
                _ => {
                    cur = None; // issuer missing from the bundle
                }
            }
        }

        if !complete {
            diagnostics.push(Diagnostic::warn(
                "CHAIN_INCOMPLETE",
                "issuer chain does not reach a self-signed root present in the bundle",
            ));
        }

        chains.push(ChainSummary {
            indices,
            complete,
            self_signed_only,
            diagnostics,
        });
    }

    chains
}
