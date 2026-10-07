use super::*;
use monero_wallet::{ringct::{clsag::Decoys, RctBase}, transaction::TransactionPrefix};

#[cfg(test)]
#[path = "joint_public_tests.rs"]
mod tests;

#[derive(Clone, PartialEq, Eq)]
struct PublicRing {
    indices: Vec<u64>,
    members: Vec<[Point; 2]>,
}

pub(super) struct PublicJoint {
    body: Transaction,
    rings: Vec<PublicRing>,
    buyer_image: CompressedPoint,
    own_image: CompressedPoint,
    own_mask: Zeroizing<Scalar>,
    own_pseudo: CompressedPoint,
    signed: Option<Value>,
}

fn strict_point(v: &Value, name: &str) -> Result<Point, Error> {
    if hex::decode(field(v, name)?)?.len() != 32 { return Err("Expected a 32-byte point".into()); }
    let p = point(v, name)?;
    if p.compress().to_bytes() != hex::decode(field(v, name)?)?.as_slice() {
        return Err("Noncanonical point".into());
    }
    Ok(p)
}

fn offsets(indices: &[u64]) -> Result<Vec<u64>, Error> {
    if indices.len() != 16 || indices.windows(2).any(|p| p[0] >= p[1]) {
        return Err("Expected sixteen strictly increasing ring indices".into());
    }
    let mut result = vec![indices[0]];
    result.extend(indices.windows(2).map(|p| p[1] - p[0]));
    Ok(result)
}

fn read_ring(v: &Value) -> Result<PublicRing, Error> {
    let indices = v["indices"].as_array().ok_or("Missing ring indices")?.iter()
        .map(|i| i.as_u64().ok_or("Invalid ring index")).collect::<Result<Vec<_>, _>>()?;
    offsets(&indices)?;
    let members = v["members"].as_array().ok_or("Missing ring members")?.iter()
        .map(|m| Ok([strict_point(m, "key")?, strict_point(m, "commitment")?]))
        .collect::<Result<Vec<_>, Error>>()?;
    if members.len() != 16 { return Err("Expected sixteen public ring members".into()); }
    let mut keys = std::collections::HashSet::new();
    for member in &members {
        if !keys.insert(member[0].compress().to_bytes()) {
            return Err("Duplicate public keys are not allowed in the shared ring".into());
        }
    }
    Ok(PublicRing { indices, members })
}

fn public_descriptor(own: &OwnInput) -> Value {
    json!({"key_image":hex::encode(own.image.to_bytes()),"role":own.role,
        "public_ring":{"indices":own.input.decoys().positions(),
            "members":own.input.decoys().ring().iter().map(|m| json!({
                "key":hex::encode(m[0].compress().to_bytes()),
                "commitment":hex::encode(m[1].compress().to_bytes())})).collect::<Vec<_>>()}})
}

fn set_ring(own: &mut OwnInput, v: &Value) -> Result<Value, Error> {
    let ring = read_ring(v)?;
    let old = own.input.decoys();
    let own_position = old.positions()[usize::from(old.signer_index())];
    let index = ring.indices.iter().position(|i| *i == own_position).ok_or("Owned ring position is missing")?;
    if ring.members[index] != [own.input.key(), own.input.commitment().commit()] {
        return Err("Public ring changes the cached owned output".into());
    }
    let decoys = Decoys::new(offsets(&ring.indices)?, u8::try_from(index)?, ring.members)
        .ok_or("Invalid shared ring")?;
    let mut bytes = Zeroizing::new(Vec::new());
    own.input.key().compress().write(&mut *bytes)?;
    own.input.key_offset().write(&mut *bytes)?;
    own.input.commitment().write(&mut *bytes)?;
    decoys.write(&mut *bytes)?;
    let input = OutputWithDecoys::read(&mut bytes.as_slice())?;
    ClsagContext::new(input.decoys().clone(), input.commitment().clone())?;
    own.input = input;
    let mut result = public_descriptor(own);
    result["descriptor"] = json!(hex::encode(own.input.serialize()));
    result["amount"] = json!(own.input.commitment().amount);
    result["input_key"] = json!(hex::encode(own.input.key().compress().to_bytes()));
    Ok(result)
}

fn read_unsigned(encoded: &str) -> Result<Transaction, Error> {
    if encoded.len() > 200_000 { return Err("Public joint body exceeds the lab limit".into()); }
    let bytes = hex::decode(encoded)?;
    if bytes.first() != Some(&2) { return Err("Expected canonical transaction version 2".into()); }
    let mut reader = &bytes[1..];
    let prefix = TransactionPrefix::read(&mut reader, 2)?;
    if prefix.inputs.len() != 2 || !(2..=16).contains(&prefix.outputs.len()) || prefix.additional_timelock != Timelock::None {
        return Err("Public joint lab requires two inputs, 2..16 outputs, and no timelock".into());
    }
    for input in &prefix.inputs {
        match input {
            Input::ToKey { amount: None, key_offsets, key_image } if key_offsets.len() == 16 => {
                if key_image.decompress().and_then(|p| p.key_image()).is_none() {
                    return Err("Invalid native input key image".into());
                }
            }
            _ => return Err("Expected native ring-16 RingCT inputs".into()),
        }
    }
    let (kind, base) = RctBase::read(2, prefix.outputs.len(), &mut reader)?.ok_or("Missing RingCT body")?;
    if kind != RctType::ClsagBulletproofPlus { return Err("Expected CLSAG Bulletproof+".into()); }
    let prunable = RctPrunable::read(kind, 16, 0, prefix.outputs.len(), &mut reader)?;
    let tx = Transaction::V2 { prefix, proofs: Some(RctProofs { base, prunable }) };
    if !reader.is_empty() || tx.serialize() != bytes { return Err("Noncanonical unsigned native body".into()); }
    let native_images = images(&tx)?;
    if native_images[0].to_bytes() <= native_images[1].to_bytes() { return Err("Native key images must be distinct and descending".into()); }
    verify_rangeproof(&tx)?;
    Ok(tx)
}

fn verify_rangeproof(tx: &Transaction) -> Result<(), Error> {
    let Transaction::V2 { proofs: Some(RctProofs { base, prunable: RctPrunable::Clsag { bulletproof, .. } }), .. } = tx
        else { return Err("Expected native CLSAG transaction".into()); };
    if !bulletproof.verify(&mut OsRng, &base.commitments) { return Err("Native Bulletproof+ verification failed".into()); }
    Ok(())
}

fn match_public_rings(body: &Transaction, supplied: &[Value]) -> Result<Vec<PublicRing>, Error> {
    if supplied.len() != 2 { return Err("Expected two public rings".into()); }
    let mut rings = Vec::new();
    for (index, image) in images(body)?.iter().enumerate() {
        let selected = supplied.iter().filter(|r| r["key_image"] == hex::encode(image.to_bytes())).collect::<Vec<_>>();
        if selected.len() != 1 { return Err("Public ring key image mismatch".into()); }
        let ring = read_ring(selected[0])?;
        let Input::ToKey { key_offsets, .. } = &body.prefix().inputs[index] else { return Err("Expected native ToKey input".into()) };
        if offsets(&ring.indices)? != *key_offsets { return Err("Public ring indices differ from the native body".into()); }
        rings.push(ring);
    }
    if rings.len() != 2 { return Err("Public joint mode requires two rings".into()); }
    let common = common_members(&rings);
    if !(1..=7).contains(&common) || 32 - common < 25 {
        return Err("Public joint mode requires 1..7 shared members and at least 25 distinct ring indices".into());
    }
    for (i, index) in rings[0].indices.iter().enumerate() {
        if let Some(j) = rings[1].indices.iter().position(|other| other == index) {
            if rings[0].members[i] != rings[1].members[j] {
                return Err("Common native ring indices must identify the same key and commitment".into());
            }
        }
    }
    Ok(rings)
}

fn common_members(rings: &[PublicRing]) -> usize {
    rings[0].indices.iter().filter(|i| rings[1].indices.contains(i)).count()
}

fn accept_public(own: &OwnInput, v: &Value) -> Result<PublicJoint, Error> {
    if own.role != "seller" { return Err("Public transcript acceptance is seller-only".into()); }
    let body = read_unsigned(field(v, "unsigned_blob")?)?;
    let native_images = images(&body)?;
    let buyer_image = strict_point(v, "buyer_image")?.compress();
    if buyer_image == own.image || !native_images.contains(&buyer_image) || !native_images.contains(&own.image) {
        return Err("Public joint buyer and seller images do not match the native inputs".into());
    }
    if hex::decode(field(v, "own_pseudo_mask")?)?.len() != 32 { return Err("Expected a 32-byte pseudo mask".into()); }
    let own_mask = Zeroizing::new(scalar(v, "own_pseudo_mask")?);
    let supplied = v["rings"].as_array().ok_or("Missing public rings")?;
    let rings = match_public_rings(&body, supplied)?;
    for (index, image) in native_images.iter().enumerate() {
        let ring = &rings[index];
        if *image == own.image && (ring.indices != own.input.decoys().positions() || ring.members != own.input.decoys().ring()) {
            return Err("Public seller ring differs from the cached private input".into());
        }
    }
    let buyer_index = native_images.iter().position(|image| *image == buyer_image).ok_or("Missing buyer input")?;
    let source_index = own.input.decoys().positions()[usize::from(own.input.decoys().signer_index())];
    if !rings[buyer_index].indices.contains(&source_index) {
        return Err("Buyer ring must authenticate the cached seller source".into());
    }
    let own_pseudo = Commitment::new(*own_mask, own.input.commitment().amount).commit().compress();
    Ok(PublicJoint { body, rings, buyer_image, own_image: own.image, own_mask, own_pseudo, signed: None })
}

fn verify_contribution_public(joint: &PublicJoint, v: &Value) -> Result<(usize, Clsag, CompressedPoint), Error> {
    let hash = joint.body.signature_hash().ok_or("Missing native signature hash")?;
    if field(v, "signature_hash")? != hex::encode(hash) { return Err("Contribution signature hash mismatch".into()); }
    let image = strict_point(v, "key_image")?.compress();
    let index = images(&joint.body)?.iter().position(|i| *i == image).ok_or("Unknown contributor image")?;
    let pseudo = strict_point(v, "pseudo_out")?.compress();
    if image == joint.own_image && pseudo != joint.own_pseudo { return Err("Seller pseudo output differs from its assigned commitment".into()); }
    let bytes = hex::decode(field(v, "clsag")?)?;
    let mut reader = bytes.as_slice();
    let clsag = Clsag::read(16, &mut reader)?;
    if !reader.is_empty() { return Err("Trailing bytes in CLSAG".into()); }
    clsag.verify(joint.rings[index].members.iter().map(|m| [m[0].compress(), m[1].compress()]).collect(),
        &image, &pseudo, &hash)?;
    Ok((index, clsag, pseudo))
}

fn verify_balance(tx: &Transaction, pseudos: &[CompressedPoint]) -> Result<(), Error> {
    let Transaction::V2 { proofs: Some(proofs), .. } = tx else { return Err("Missing native proofs".into()); };
    let mut balance = EdwardsPoint::identity();
    for pseudo in pseudos { balance += pseudo.decompress().ok_or("Invalid pseudo output")?.into(); }
    for commitment in &proofs.base.commitments { balance -= commitment.decompress().ok_or("Invalid output commitment")?.into(); }
    balance -= Commitment::new(Scalar::ZERO, proofs.base.fee).commit().into();
    if balance != EdwardsPoint::identity() { return Err("Native commitment balance failed".into()); }
    Ok(())
}

fn sign_public(own: &OwnInput, joint: &mut PublicJoint, v: &Value) -> Result<Value, Error> {
    if joint.signed.is_some() { return Err("This process already signed its immutable public joint body".into()); }
    let (index, _, buyer_pseudo) = verify_contribution_public(joint, &v["prior_contribution"])?;
    if images(&joint.body)?[index] != joint.buyer_image { return Err("Seller requires the designated buyer contribution first".into()); }
    verify_balance(&joint.body, &[buyer_pseudo, joint.own_pseudo])?;
    if own.role != "seller" || own.image != joint.own_image || pubkey(*own.key) != own.input.key() {
        return Err("Cached seller input ownership mismatch".into());
    }
    let hash = joint.body.signature_hash().ok_or("Missing native signature hash")?;
    let (clsag, pseudo) = Clsag::sign(&mut OsRng, vec![(own.key.clone(),
        ClsagContext::new(own.input.decoys().clone(), own.input.commitment().clone())?)], *joint.own_mask, hash)?
        .pop().ok_or("No CLSAG produced")?;
    let mut bytes = Vec::new(); clsag.write(&mut bytes)?;
    let contribution = json!({"key_image":hex::encode(own.image.to_bytes()),"signature_hash":hex::encode(hash),
        "clsag":hex::encode(bytes),"pseudo_out":hex::encode(pseudo.compress().to_bytes()),"role":"seller"});
    verify_contribution_public(joint, &contribution)?;
    joint.signed = Some(contribution.clone());
    Ok(contribution)
}

fn assemble_public(joint: &PublicJoint, supplied: &[Value]) -> Result<Value, Error> {
    if supplied.len() != 2 { return Err("Two CLSAG contributions are required".into()); }
    let mut contributions = supplied.iter().map(|v| verify_contribution_public(joint, v)).collect::<Result<Vec<_>, _>>()?;
    contributions.sort_by_key(|c| c.0);
    if contributions[0].0 != 0 || contributions[1].0 != 1 { return Err("Duplicate contributor".into()); }
    verify_balance(&joint.body, &contributions.iter().map(|c| c.2).collect::<Vec<_>>())?;
    verify_rangeproof(&joint.body)?;
    let mut tx = joint.body.clone();
    let Transaction::V2 { proofs: Some(RctProofs { prunable: RctPrunable::Clsag { clsags, pseudo_outs, .. }, .. }), .. } = &mut tx
        else { return Err("Expected native CLSAG transaction".into()); };
    for (_, clsag, pseudo) in contributions { clsags.push(clsag); pseudo_outs.push(pseudo); }
    Ok(json!({"blob":hex::encode(tx.serialize()),"txid":hex::encode(tx.hash()),"weight":tx.weight(),
        "signature_hash":hex::encode(tx.signature_hash().ok_or("Missing signature hash")?),
        "verified_clsags":2,"verified_balance":true,"verified_bulletproof_plus":true,"shared_ring":true,
        "shared_ring_members":common_members(&joint.rings),"distinct_ring_members":32-common_members(&joint.rings),"identical_rings":false,
        "policy_verified_by_backend":false,"ring_chain_membership_verified_by_backend":false}))
}

fn verify_native_public(joint: &PublicJoint, encoded: &str) -> Result<Value, Error> {
    if encoded.len() > 200_000 { return Err("Public joint transaction exceeds the lab limit".into()); }
    let bytes = hex::decode(encoded)?;
    let mut reader = bytes.as_slice();
    let mut tx = Transaction::read(&mut reader)?;
    if !reader.is_empty() || tx.serialize() != bytes { return Err("Noncanonical native transaction".into()); }
    let hash = tx.signature_hash().ok_or("Missing native signature hash")?;
    let native_images = images(&tx)?;
    let Transaction::V2 { proofs: Some(RctProofs { prunable: RctPrunable::Clsag { clsags, pseudo_outs, .. }, .. }), .. } = &mut tx
        else { return Err("Expected native CLSAG transaction".into()); };
    if clsags.len() != 2 || pseudo_outs.len() != 2 || native_images.len() != 2 { return Err("Expected two complete native signatures".into()); }
    let mut contributions = Vec::new();
    for i in 0..2 {
        let mut signature = Vec::new(); clsags[i].write(&mut signature)?;
        contributions.push(json!({"signature_hash":hex::encode(hash),"key_image":hex::encode(native_images[i].to_bytes()),
            "pseudo_out":hex::encode(pseudo_outs[i].to_bytes()),"clsag":hex::encode(signature)}));
    }
    clsags.clear(); pseudo_outs.clear();
    if tx.serialize() != joint.body.serialize() { return Err("Native transaction changed the pinned immutable body".into()); }
    let mut result = assemble_public(joint, &contributions)?;
    if result["blob"] != encoded { return Err("Native reconstruction mismatch".into()); }
    result["valid"] = json!(true);
    Ok(result)
}

fn check_public(v: &Value) -> Result<Value, Error> {
    let encoded = field(v, "blob")?;
    if encoded.len() > 200_000 { return Err("Public joint transaction exceeds the lab limit".into()); }
    let bytes = hex::decode(encoded)?;
    let mut reader = bytes.as_slice();
    let tx = Transaction::read(&mut reader)?;
    if !reader.is_empty() || tx.serialize() != bytes { return Err("Noncanonical native transaction".into()); }
    let Transaction::V2 { proofs: Some(RctProofs { prunable: RctPrunable::Clsag { clsags, pseudo_outs, .. }, .. }), .. } = &tx
        else { return Err("Expected native CLSAG transaction".into()); };
    if clsags.len() != 2 || pseudo_outs.len() != 2 { return Err("Expected two complete native signatures".into()); }
    let mut unsigned = tx.clone();
    let Transaction::V2 { proofs: Some(RctProofs { prunable: RctPrunable::Clsag { clsags: unsigned_clsags, pseudo_outs: unsigned_pseudos, .. }, .. }), .. } = &mut unsigned
        else { unreachable!() };
    unsigned_clsags.clear(); unsigned_pseudos.clear();
    let body = read_unsigned(&hex::encode(unsigned.serialize()))?;
    let rings = match_public_rings(&body, v["rings"].as_array().ok_or("Missing public rings")?)?;
    let hash = tx.signature_hash().ok_or("Missing native signature hash")?;
    let native_images = images(&body)?;
    for i in 0..2 {
        clsags[i].verify(rings[i].members.iter().map(|m| [m[0].compress(), m[1].compress()]).collect(),
            &native_images[i], &pseudo_outs[i], &hash)?;
    }
    verify_balance(&body, pseudo_outs)?;
    Ok(json!({"valid":true,"txid":hex::encode(tx.hash()),"signature_hash":hex::encode(hash),
        "verified_clsags":2,"verified_balance":true,"verified_bulletproof_plus":true,"shared_ring":true,
        "shared_ring_members":common_members(&rings),"distinct_ring_members":32-common_members(&rings),"identical_rings":false,
        "hidden_source_guard_verified_by_backend":false,
        "policy_verified_by_backend":false,"ring_chain_membership_verified_by_backend":false}))
}

pub(super) async fn handle(v: &Value, state: &mut State, rpc_cache: &mut Option<(String, Rpc)>) -> Result<Value, Error> {
    match field(v, "command")? {
        "joint_check_public" => check_public(v),
        "joint_public_descriptor" => Ok(public_descriptor(state.own.as_ref().ok_or("No owned input")?)),
        "joint_set_ring" => {
            if state.joint.is_some() || state.public.is_some() { return Err("Cannot change a pinned joint ring".into()); }
            set_ring(state.own.as_mut().ok_or("No owned input")?, v)
        }
        "joint_accept_public" => {
            if state.joint.is_some() || state.public.is_some() { return Err("Joint intent is already pinned".into()); }
            let joint = accept_public(state.own.as_ref().ok_or("No owned input")?, v)?;
            let result = json!({"accepted":true,"unsigned_blob":hex::encode(joint.body.serialize()),
                "signature_hash":hex::encode(joint.body.signature_hash().ok_or("Missing signature hash")?),
                "shared_ring":true,"shared_ring_members":common_members(&joint.rings),"distinct_ring_members":32-common_members(&joint.rings),
                "identical_rings":false,"policy_verified_by_backend":false,"ring_chain_membership_verified_by_backend":false});
            state.public = Some(joint); Ok(result)
        }
        "joint_sign_public" => sign_public(state.own.as_ref().ok_or("No owned input")?, state.public.as_mut().ok_or("No public joint body")?, v),
        "joint_assemble_public" => assemble_public(state.public.as_ref().ok_or("No public joint body")?, v["contributions"].as_array().ok_or("Missing contributions")?),
        "joint_verify_public" => verify_native_public(state.public.as_ref().ok_or("No public joint body")?, field(v, "blob")?),
        "joint_submit_public" => {
            let own = state.own.as_ref().ok_or("No owned input")?;
            let joint = state.public.as_ref().ok_or("No public joint body")?;
            if own.role != "seller" || joint.signed.is_none() { return Err("Only a signed seller session may submit".into()); }
            let blob = field(v, "blob")?;
            let verified = verify_native_public(joint, blob)?;
            let do_sanity_checks = match v.get("do_sanity_checks") {
                None => true,
                Some(value) => value.as_bool().ok_or("do_sanity_checks must be a boolean")?,
            };
            let rpc = checked_rpc(v, rpc_cache).await?;
            let result: Value = serde_json::from_str(&rpc.rpc_call("send_raw_transaction",
                Some(json!({"tx_as_hex":blob,"do_not_relay":false,"do_sanity_checks":do_sanity_checks}).to_string()), 16384).await?)?;
            if result["status"] != "OK" { return Err(format!("Seller submission rejected: {result}").into()); }
            Ok(json!({"status":"OK","txid":verified["txid"],"submitted_by":"seller","do_sanity_checks":do_sanity_checks}))
        }
        _ => Err("Unknown joint command".into()),
    }
}
