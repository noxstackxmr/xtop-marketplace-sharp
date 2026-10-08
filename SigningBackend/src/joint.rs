use super::*;
use curve25519_dalek::{edwards::EdwardsPoint, traits::Identity};
use monero_wallet::{
    ed25519::Commitment,
    ringct::{clsag::{Clsag, ClsagContext}, RctPrunable, RctProofs},
    transaction::{Input, Transaction},
};

#[cfg(test)]
#[path = "joint_tests.rs"]
mod tests;

#[path = "joint_public.rs"]
mod public;

struct OwnInput {
    input: OutputWithDecoys,
    key: Zeroizing<Scalar>,
    image: CompressedPoint,
    role: String,
}

struct Joint {
    intent: SignableTransaction,
    images: Vec<CompressedPoint>, // original intent input order
    inputs: Vec<OutputWithDecoys>, // native descending key-image order
    masks: Vec<Scalar>, // native descending key-image order
    body: Transaction,
    bound: bool,
    signed: Option<Value>,
    buyer_image: CompressedPoint,
}

#[derive(Default)]
pub(super) struct State { own: Option<OwnInput>, joint: Option<Joint>, public: Option<public::PublicJoint> }

fn encoded_scalar(s: Scalar) -> String { hex::encode(s.into().to_bytes()) }
fn address(v: &Value) -> Result<MoneroAddress, Error> {
    Ok(MoneroAddress::new(Network::Mainnet, AddressType::Legacy,
        point(v, "spend_public")?, point(v, "view_public")?))
}
fn payments(v: &Value) -> Result<Vec<(MoneroAddress, u64)>, Error> {
    v["payments"].as_array().ok_or("Missing payments")?.iter().map(|p|
        Ok((address(p)?, p["amount"].as_u64().ok_or("Invalid payment amount")?))).collect()
}
fn decoded_point(v: &Value, name: &str) -> Result<CompressedPoint, Error> {
    Ok(point(v, name)?.compress())
}
fn images(body: &Transaction) -> Result<Vec<CompressedPoint>, Error> {
    body.prefix().inputs.iter().map(|i| match i {
        Input::ToKey { key_image, .. } => Ok(*key_image),
        _ => Err("Joint input is not a native ToKey input".into()),
    }).collect()
}
fn check_policy(intent: &SignableTransaction, v: &Value) -> Result<(), Error> {
    let (actual, change) = intent.xtop_joint_payment_plan();
    let normalize = |ps: Vec<(MoneroAddress, u64)>| {
        let mut ps = ps.into_iter().map(|(a, n)| (a.to_string(), n)).collect::<Vec<_>>();
        ps.sort(); ps
    };
    if normalize(actual) != normalize(payments(v)?) || change != Some(address(&v["change"])?) {
        return Err("Joint payments or change do not match the authorized plan".into());
    }
    Ok(())
}

fn read_descriptor(v: &Value) -> Result<OutputWithDecoys, Error> {
    let bytes = hex::decode(field(v, "descriptor")?)?;
    let mut reader = bytes.as_slice();
    let input = OutputWithDecoys::read(&mut reader)?;
    if !reader.is_empty() || input.decoys().len() != 16 { return Err("Invalid joint descriptor".into()); }
    if input.decoys().signer_ring_members() != [input.key(), input.commitment().commit()] {
        return Err("Descriptor does not match its real ring member".into());
    }
    ClsagContext::new(input.decoys().clone(), input.commitment().clone())?;
    Ok(input)
}

fn accept(own: &OwnInput, package: &Value, expected_blob: &str, policy: &Value) -> Result<Joint, Error> {
    let bytes = Zeroizing::new(hex::decode(field(package, "intent")?)?);
    let mut reader = bytes.as_slice();
    let intent = SignableTransaction::read(&mut reader)?;
    if !reader.is_empty() { return Err("Trailing bytes in joint intent".into()); }
    check_policy(&intent, policy)?;
    let images_original = package["key_images"].as_array().ok_or("Missing key images")?
        .iter().map(|i| decoded_point(&json!({"image":i}), "image")).collect::<Result<Vec<_>,_>>()?;
    let (body, inputs, sum) = intent.clone().xtop_joint_context(images_original.clone())?;
    if !(2..=6).contains(&inputs.len()) || inputs.iter().any(|input| input.decoys().len() != 16) {
        return Err("Joint lab requires two to six ring-16 inputs".into());
    }
    if hex::encode(body.serialize()) != expected_blob { return Err("Joint unsigned body mismatch".into()); }
    let sorted_images = images(&body)?;
    if sorted_images.windows(2).any(|pair| pair[0] == pair[1]) { return Err("Duplicate joint input image".into()); }
    let own_index = sorted_images.iter().position(|i| *i == own.image).ok_or("Own image missing from joint body")?;
    if inputs[own_index] != own.input { return Err("Joint input differs from cached owned input".into()); }
    let buyer_image = if !package["buyer_image"].is_null() {
        decoded_point(package, "buyer_image")?
    } else if inputs.len() == 2 {
        if own.role == "buyer" { own.image } else { sorted_images[1 - own_index] }
    } else { return Err("Batch intent requires an explicit buyer image".into()); };
    if !sorted_images.contains(&buyer_image) || (own.role == "buyer") != (own.image == buyer_image) {
        return Err("Owned input does not match the joint buyer role".into());
    }
    let mut masks = Vec::new();
    let supplied = package["pseudo_masks"].as_array().ok_or("Missing pseudo masks")?;
    if supplied.len() != inputs.len() { return Err("Expected one pseudo mask per input".into()); }
    for image in &sorted_images {
        let selected = supplied.iter().filter(|m| m["key_image"] == hex::encode(image.to_bytes())).collect::<Vec<_>>();
        if selected.len() != 1 { return Err("Pseudo mask key image mismatch".into()); }
        masks.push(scalar(selected[0], "mask")?);
    }
    if masks.iter().map(|s| (*s).into()).sum::<curve25519_dalek::Scalar>() != sum.into() {
        return Err("Joint pseudo masks do not balance the outputs".into());
    }
    Ok(Joint { intent, images: images_original, inputs, masks, body, bound: false, signed: None, buyer_image })
}

fn verify_contribution(joint: &Joint, v: &Value) -> Result<(usize, Clsag, CompressedPoint), Error> {
    if !joint.bound { return Err("Joint transaction has not been bound to its carrier".into()); }
    let hash = joint.body.signature_hash().ok_or("Missing native signature hash")?;
    if field(v, "signature_hash")? != hex::encode(hash) { return Err("Contribution signature hash mismatch".into()); }
    let image = decoded_point(v, "key_image")?;
    let index = images(&joint.body)?.iter().position(|i| *i == image).ok_or("Unknown contributor image")?;
    let pseudo = decoded_point(v, "pseudo_out")?;
    if pseudo != Commitment::new(joint.masks[index], joint.inputs[index].commitment().amount).commit().compress() {
        return Err("Contribution uses an unassigned pseudo-output mask".into());
    }
    let bytes = hex::decode(field(v, "clsag")?)?;
    let mut reader = bytes.as_slice();
    let clsag = Clsag::read(16, &mut reader)?;
    if !reader.is_empty() { return Err("Trailing bytes in CLSAG".into()); }
    clsag.verify(joint.inputs[index].decoys().ring().iter().map(|r| [r[0].compress(), r[1].compress()]).collect(),
        &image, &pseudo, &hash)?;
    Ok((index, clsag, pseudo))
}

fn chain_outputs(joint: &Joint) -> Result<Vec<Value>, Error> {
    let mut outputs = Vec::new();
    for (native, supplied) in joint.body.prefix().inputs.iter().zip(&joint.inputs) {
        let Input::ToKey { amount: None, key_offsets, .. } = native else { return Err("Expected RingCT input".into()) };
        if key_offsets.len() != 16 || key_offsets.as_slice() != supplied.decoys().offsets() {
            return Err("Ring offsets differ from transaction".into());
        }
        let mut absolute = 0u64;
        for (i, offset) in key_offsets.iter().enumerate() {
            if i > 0 && *offset == 0 { return Err("Duplicate ring index".into()); }
            absolute = absolute.checked_add(*offset).ok_or("Ring index overflow")?;
            outputs.push(json!({"amount":0,"index":absolute}));
        }
    }
    Ok(outputs)
}

fn match_chain_outputs(joint: &Joint, response: &Value) -> Result<(), Error> {
    if response["status"] != "OK" || response["untrusted"] == true { return Err("Untrusted ring lookup".into()); }
    let outputs = response["outs"].as_array().ok_or("Missing chain outputs")?;
    if outputs.len() != joint.inputs.len() * 16 { return Err("Incomplete ring lookup".into()); }
    for (actual, expected) in outputs.iter().zip(joint.inputs.iter().flat_map(|i| i.decoys().ring())) {
        if actual["unlocked"] != true || actual["key"] != hex::encode(expected[0].compress().to_bytes()) ||
            actual["mask"] != hex::encode(expected[1].compress().to_bytes()) {
            return Err("Ring member differs from unlocked blockchain output".into());
        }
    }
    Ok(())
}

async fn check_chain_inputs(joint: &Joint, rpc: &Rpc) -> Result<(), Error> {
    let rate = rpc.fee_rate(FeePriority::Unimportant, u64::MAX).await?;
    let mut complete = joint.body.clone();
    let Transaction::V2 { proofs: Some(RctProofs { base, prunable: RctPrunable::Clsag { clsags, pseudo_outs, .. } }), .. } = &mut complete
        else { return Err("Expected CLSAG transaction".into()) };
    let fee = base.fee;
    *clsags = (0..joint.inputs.len()).map(|_| Clsag { D: CompressedPoint::G, s: vec![Scalar::ZERO;16], c1: Scalar::ZERO }).collect();
    *pseudo_outs = vec![CompressedPoint::G;joint.inputs.len()];
    if u128::from(fee) < rate.calculate_fee_from_weight(u64::try_from(complete.weight())?) {
        return Err("Fee quote is below the current node estimate".into());
    }
    let outputs = chain_outputs(joint)?;
    let response: Value = serde_json::from_str(&rpc.rpc_call("get_outs",
        Some(json!({"outputs":outputs,"get_txid":false}).to_string()), 131072).await?)?;
    match_chain_outputs(joint, &response)?;
    let spent: Value = serde_json::from_str(&rpc.rpc_call("is_key_image_spent",
        Some(json!({"key_images":images(&joint.body)?.iter().map(|i|hex::encode(i.to_bytes())).collect::<Vec<_>>()} ).to_string()), 16384).await?)?;
    let statuses = spent["spent_status"].as_array().ok_or("Missing spent status")?;
    if spent["status"] != "OK" || spent["untrusted"] == true || statuses.len() != joint.inputs.len() || statuses.iter().any(|s| s.as_u64() != Some(0)) {
        return Err("Input is spent or pending".into());
    }
    Ok(())
}

fn sign(own: &OwnInput, joint: &mut Joint, v: &Value) -> Result<Value, Error> {
    if joint.signed.is_some() { return Err("This process already signed its immutable joint body".into()); }
    if !joint.bound { return Err("Bind the final carrier before signing".into()); }
    if own.role == "seller" {
        let (prior_index, _, _) = verify_contribution(joint, &v["prior_contribution"])?;
        if images(&joint.body)?[prior_index] != joint.buyer_image { return Err("Seller requires the designated buyer contribution first".into()); }
    } else if !v["prior_contribution"].is_null() {
        return Err("Buyer must sign first".into());
    }
    let index = images(&joint.body)?.iter().position(|i| *i == own.image).ok_or("Own image missing")?;
    if joint.inputs[index] != own.input || pubkey(*own.key) != own.input.key() {
        return Err("Cached input ownership mismatch".into());
    }
    let hash = joint.body.signature_hash().ok_or("Missing signature hash")?;
    let (clsag, pseudo) = Clsag::sign(&mut OsRng, vec![(own.key.clone(),
        ClsagContext::new(own.input.decoys().clone(), own.input.commitment().clone())?)], joint.masks[index], hash)?
        .pop().ok_or("No CLSAG produced")?;
    let mut bytes = Vec::new(); clsag.write(&mut bytes)?;
    let contribution = json!({"key_image":hex::encode(own.image.to_bytes()),
        "signature_hash":hex::encode(hash),"clsag":hex::encode(bytes),
        "pseudo_out":hex::encode(pseudo.compress().to_bytes()),"role":own.role});
    verify_contribution(joint, &contribution)?;
    joint.signed = Some(contribution.clone());
    Ok(contribution)
}

fn assemble(joint: &Joint, contributions: &[Value]) -> Result<Value, Error> {
    if contributions.len() != joint.inputs.len() { return Err("All native CLSAG contributions are required".into()); }
    let mut contributions = contributions.iter().map(|v| verify_contribution(joint, v)).collect::<Result<Vec<_>,_>>()?;
    contributions.sort_by_key(|c| c.0);
    if contributions.iter().enumerate().any(|(i, c)| c.0 != i) { return Err("Duplicate contributor".into()); }
    let mut tx = joint.body.clone();
    let Transaction::V2 { proofs: Some(RctProofs { base, prunable: RctPrunable::Clsag { bulletproof, clsags, pseudo_outs } }), .. } = &mut tx
        else { return Err("Expected native CLSAG transaction".into()); };
    let mut balance = EdwardsPoint::identity();
    for (_, clsag, pseudo) in contributions {
        balance += pseudo.decompress().ok_or("Invalid pseudo output")?.into();
        clsags.push(clsag); pseudo_outs.push(pseudo);
    }
    for commitment in &base.commitments { balance -= commitment.decompress().ok_or("Invalid output commitment")?.into(); }
    balance -= Commitment::new(Scalar::ZERO, base.fee).commit().into();
    if balance != EdwardsPoint::identity() { return Err("Native commitment balance failed".into()); }
    if !bulletproof.verify(&mut OsRng, &base.commitments) { return Err("Native Bulletproof+ verification failed".into()); }
    Ok(json!({"blob":hex::encode(tx.serialize()),"txid":hex::encode(tx.hash()),"weight":tx.weight(),
        "signature_hash":hex::encode(tx.signature_hash().ok_or("Missing signature hash")?),
        "verified_clsags":joint.inputs.len(),"verified_balance":true,"verified_bulletproof_plus":true}))
}

fn verify_native(joint: &Joint, encoded: &str) -> Result<Value, Error> {
    if !joint.bound { return Err("Bind the final carrier before verification".into()); }
    let bytes = hex::decode(encoded)?;
    let mut reader = bytes.as_slice();
    let mut tx = Transaction::read(&mut reader)?;
    if !reader.is_empty() || tx.serialize() != bytes { return Err("Noncanonical native transaction".into()); }
    let hash = tx.signature_hash().ok_or("Missing native signature hash")?;
    let native_images = images(&tx)?;
    let Transaction::V2 { proofs: Some(RctProofs { prunable: RctPrunable::Clsag { clsags, pseudo_outs, .. }, .. }), .. } = &mut tx
        else { return Err("Expected native CLSAG transaction".into()); };
    if clsags.len() != joint.inputs.len() || pseudo_outs.len() != joint.inputs.len() || native_images.len() != joint.inputs.len() {
        return Err("Expected one native signature per input".into());
    }
    let mut contributions = Vec::new();
    for i in 0..joint.inputs.len() {
        let mut signature = Vec::new(); clsags[i].write(&mut signature)?;
        contributions.push(json!({"signature_hash":hex::encode(hash),"key_image":hex::encode(native_images[i].to_bytes()),
            "pseudo_out":hex::encode(pseudo_outs[i].to_bytes()),"clsag":hex::encode(signature)}));
    }
    clsags.clear(); pseudo_outs.clear();
    if tx.serialize() != joint.body.serialize() { return Err("Native transaction changed the pinned immutable body".into()); }
    let verified = assemble(joint, &contributions)?;
    if verified["blob"] != encoded { return Err("Native reconstruction mismatch".into()); }
    Ok(json!({"valid":true,"txid":verified["txid"],"verified_clsags":joint.inputs.len(),
        "verified_balance":true,"verified_bulletproof_plus":true}))
}

async fn prepare_own(v: &Value, rpc: &Rpc) -> Result<(OwnInput, Value), Error> {
    let role = field(v, "role")?;
    if role != "buyer" && role != "seller" { return Err("Role must be buyer or seller".into()); }
    let spend = Zeroizing::new(scalar(v, "spend_secret")?);
    let view = ViewPair::new(pubkey(*spend), Zeroizing::new(scalar(v, "view_secret")?))?;
    let mut scanner = Scanner::new(view);
    let tip = rpc.latest_block_number().await.map_err(|e| format!("get_height: {e}"))?;
    let height = usize::try_from(v["input_height"].as_u64().ok_or("Missing input height")?)?;
    let txid = field(v, "input_txid")?;
    let index = v["input_index"].as_u64().ok_or("Missing input index")?;
    let block = rpc.block_by_number(height).await.map_err(|e| format!("get_block {height}: {e}"))?;
    let miner = block.miner_transaction().hash();
    let outputs = scanner.scan(rpc.expand_to_scannable_block(block).await.map_err(|e| format!("expand block: {e}"))?)?.ignore_additional_timelock();
    let output = outputs.into_iter().find(|o| o.index_in_transaction() == index && hex::encode(o.transaction()) == txid)
        .ok_or("No matching owned joint input")?;
    let is_miner = output.transaction() == miner;
    let age = if is_miner { 60 } else { 10 };
    if tip < height.checked_add(age).ok_or("Height overflow")? { return Err(format!("Input requires {age} blocks of age").into()); }
    match output.additional_timelock() {
        Timelock::None => (), Timelock::Block(unlock) if is_miner && unlock <= tip => (),
        _ => return Err("Additional timelocks are not supported by the lab".into()),
    }
    let key = Zeroizing::new(Scalar::from((*spend).into() + output.key_offset().into()));
    if pubkey(*key) != output.key() { return Err("Joint input ownership failed".into()); }
    let image = Point::from((*key).into() * Point::biased_hash(output.key().compress().to_bytes()).into()).compress();
    let status: Value = serde_json::from_str(&rpc.rpc_call("is_key_image_spent", Some(json!({"key_images":[hex::encode(image.to_bytes())]}).to_string()),16384)
        .await.map_err(|e| format!("is_key_image_spent: {e}"))?)?;
    if status["spent_status"][0] != 0 { return Err("Joint input is spent or pending".into()); }
    let input = OutputWithDecoys::fingerprintable_deterministic_new(&mut OsRng, rpc, 16, tip, output).await.map_err(|e| format!("select decoys: {e}"))?;
    let result = json!({"descriptor":hex::encode(input.serialize()),"key_image":hex::encode(image.to_bytes()),
        "amount":input.commitment().amount,"input_key":hex::encode(input.key().compress().to_bytes()),"role":role});
    Ok((OwnInput { input, key, image, role:role.to_owned() }, result))
}

pub(super) async fn handle(v: &Value, state: &mut State, rpc_cache: &mut Option<(String, Rpc)>) -> Result<Value, Error> {
    match field(v, "command")? {
        "joint_input" => {
            if state.own.is_some() { return Err("This process already owns a joint input".into()); }
            let rpc = checked_rpc(v, rpc_cache).await?;
            let (own, result) = prepare_own(v, &rpc).await?;
            state.own = Some(own); Ok(result)
        }
        "joint_prepare" => {
            if state.joint.is_some() || state.public.is_some() { return Err("Joint intent is already pinned".into()); }
            let own = state.own.as_ref().ok_or("Prepare an owned input first")?;
            if own.role != "buyer" { return Err("Only the buyer constructs the joint intent".into()); }
            let rpc = checked_rpc(v, rpc_cache).await?;
            let descriptors = v["inputs"].as_array().ok_or("Missing descriptors")?;
            if !(2..=6).contains(&descriptors.len()) { return Err("Expected two to six input descriptors".into()); }
            let inputs = descriptors.iter().map(read_descriptor).collect::<Result<Vec<_>,_>>()?;
            let images = descriptors.iter().map(|d| decoded_point(d,"key_image")).collect::<Result<Vec<_>,_>>()?;
            let mut outgoing = Zeroizing::new([0;32]); OsRng.fill_bytes(outgoing.as_mut());
            let secret = TransactionKeys::new(&outgoing, inputs.iter().map(|i| (i.key(),i.commitment().commit())).collect()).next().ok_or("Missing transaction key")?;
            let len = usize::try_from(v["message_length"].as_u64().ok_or("Missing carrier length")?)?;
            if len == 0 || len > 1024 { return Err("Invalid carrier length".into()); }
            let fee = rpc.fee_rate(FeePriority::Unimportant,u64::MAX).await.map_err(|e| format!("fee estimate: {e}"))?;
            let intent = SignableTransaction::new(RctType::ClsagBulletproofPlus,outgoing,inputs,payments(v)?,
                Change::fingerprintable(Some(address(&v["change"])?)),vec![0;len].chunks(254).map(<[u8]>::to_vec).collect(),fee)?;
            let (body, _, sum) = intent.clone().xtop_joint_context(images.clone())?;
            let sorted = self::images(&body)?;
            let mut remaining: curve25519_dalek::Scalar = sum.into();
            let mut assigned = Vec::new();
            for (i, image) in sorted.iter().enumerate() {
                let mask = if i + 1 == sorted.len() { Scalar::from(remaining) } else { Scalar::random(&mut OsRng) };
                remaining -= mask.into();
                assigned.push(json!({"key_image":hex::encode(image.to_bytes()),"mask":encoded_scalar(mask)}));
            }
            let package = json!({"intent":hex::encode(intent.serialize()),
                "key_images":images.iter().map(|i| hex::encode(i.to_bytes())).collect::<Vec<_>>(),
                "buyer_image":hex::encode(own.image.to_bytes()), "pseudo_masks":assigned});
            let unsigned = hex::encode(body.serialize());
            state.joint = Some(accept(own,&package,&unsigned,v)?);
            Ok(json!({"package":package,"unsigned_blob":unsigned,"transaction_secret":encoded_scalar(*secret),"fee":intent.necessary_fee()}))
        }
        "joint_accept" => {
            if state.joint.is_some() || state.public.is_some() { return Err("Joint intent is already pinned".into()); }
            let own = state.own.as_ref().ok_or("Prepare an owned input first")?;
            let joint = accept(own,&v["package"],field(v,"unsigned_blob")?,v)?;
            let rpc = checked_rpc(v, rpc_cache).await?;
            check_chain_inputs(&joint, &rpc).await?;
            let result = json!({"accepted":true,"unsigned_blob":hex::encode(joint.body.serialize()),"fee":joint.intent.necessary_fee()});
            state.joint = Some(joint); Ok(result)
        }
        "joint_bind" => {
            let joint = state.joint.as_mut().ok_or("No joint intent")?;
            if joint.bound { return Err("Joint body is already bound and immutable".into()); }
            let mut intent = joint.intent.clone();
            intent.xtop_replace_data(hex::decode(field(v,"message")?)?)?;
            let (body, inputs, sum) = intent.clone().xtop_joint_context(joint.images.clone())?;
            if inputs != joint.inputs || sum.into() != joint.masks.iter().map(|m| (*m).into()).sum::<curve25519_dalek::Scalar>() {
                return Err("Carrier changed the input context or output masks".into());
            }
            let result = json!({"unsigned_blob":hex::encode(body.serialize()),"signature_hash":hex::encode(body.signature_hash().ok_or("Missing signature hash")?)});
            joint.intent = intent; joint.body = body; joint.bound = true; Ok(result)
        }
        "joint_sign" => sign(state.own.as_ref().ok_or("No owned input")?,state.joint.as_mut().ok_or("No joint intent")?,v),
        "joint_check_inputs" => {
            let rpc = checked_rpc(v, rpc_cache).await?;
            check_chain_inputs(state.joint.as_ref().ok_or("No joint intent")?, &rpc).await?;
            Ok(json!({"valid":true}))
        }
        "joint_assemble" => assemble(state.joint.as_ref().ok_or("No joint intent")?,v["contributions"].as_array().ok_or("Missing contributions")?),
        "joint_submit" => {
            let own = state.own.as_ref().ok_or("No owned input")?;
            let joint = state.joint.as_ref().ok_or("No joint intent")?;
            if own.role != "seller" || joint.signed.is_none() { return Err("Only a signed seller session may submit".into()); }
            let blob = field(v, "blob")?;
            let verified = verify_native(joint, blob)?;
            let rpc = checked_rpc(v, rpc_cache).await?;
            let result: Value = serde_json::from_str(&rpc.rpc_call("send_raw_transaction",
                Some(json!({"tx_as_hex":blob,"do_not_relay":false}).to_string()), 16384).await?)?;
            if result["status"] != "OK" { return Err(format!("Seller submission rejected: {result}").into()); }
            Ok(json!({"status":"OK","txid":verified["txid"],"submitted_by":"seller"}))
        }
        "joint_verify" => verify_native(state.joint.as_ref().ok_or("No joint intent")?,field(v,"blob")?),
        _ => public::handle(v, state, rpc_cache).await,
    }
}
