use super::*;
use monero_wallet::{interface::FeeRate, ringct::clsag::Decoys};

pub(super) fn own(role: &str, amount: u64) -> OwnInput {
    let key = Zeroizing::new(Scalar::random(&mut OsRng));
    let public = pubkey(*key);
    let commitment = Commitment::new(Scalar::random(&mut OsRng), amount);
    let mut ring = (0..16).map(|_| [pubkey(Scalar::random(&mut OsRng)),
        Commitment::new(Scalar::random(&mut OsRng), 12345).commit()]).collect::<Vec<_>>();
    ring[7] = [public, commitment.commit()];
    let decoys = Decoys::new(vec![1;16],7,ring).unwrap();
    let mut descriptor = Vec::new();
    public.compress().write(&mut descriptor).unwrap();
    Scalar::ZERO.write(&mut descriptor).unwrap();
    commitment.write(&mut descriptor).unwrap();
    decoys.write(&mut descriptor).unwrap();
    let input = OutputWithDecoys::read(&mut descriptor.as_slice()).unwrap();
    let image = Point::from((*key).into() * Point::biased_hash(public.compress().to_bytes()).into()).compress();
    OwnInput { input,key,image,role:role.to_owned() }
}

pub(super) fn destination(amount: Option<u64>) -> Value {
    let mut v = json!({"spend_public":hex::encode(pubkey(Scalar::random(&mut OsRng)).compress().to_bytes()),
        "view_public":hex::encode(pubkey(Scalar::random(&mut OsRng)).compress().to_bytes())});
    if let Some(amount) = amount { v["amount"] = json!(amount); }
    v
}

#[tokio::test]
async fn five_nfts_one_buyer_input_native_batch() {
    let mut owners = vec![own("buyer", 50_000_000)];
    for _ in 0..5 { owners.push(own("seller", 1_000)); }
    let policy = json!({"payments":[destination(Some(5_000_000)), destination(Some(125_000)),
        destination(Some(1_000)),destination(Some(1_000)),destination(Some(1_000)),destination(Some(1_000)),destination(Some(1_000))],
        "change":destination(None)});
    let intent = SignableTransaction::new(RctType::ClsagBulletproofPlus,Zeroizing::new([31;32]),
        owners.iter().map(|o|o.input.clone()).collect(),payments(&policy).unwrap(),
        Change::fingerprintable(Some(address(&policy["change"]).unwrap())),
        vec![0;1006].chunks(254).map(<[u8]>::to_vec).collect(),FeeRate::new(1,1).unwrap()).unwrap();
    let original = owners.iter().map(|o|o.image).collect::<Vec<_>>();
    let (body,_,sum) = intent.clone().xtop_joint_context(original.clone()).unwrap();
    assert_eq!(body.prefix().outputs.len(),8);
    let sorted = images(&body).unwrap();
    let mut remaining: curve25519_dalek::Scalar = sum.into();
    let mut masks = Vec::new();
    for (i,image) in sorted.iter().enumerate() {
        let mask = if i + 1 == sorted.len() {Scalar::from(remaining)} else {Scalar::random(&mut OsRng)};
        remaining -= mask.into();
        masks.push(json!({"key_image":hex::encode(image.to_bytes()),"mask":encoded_scalar(mask)}));
    }
    let package = json!({"intent":hex::encode(intent.serialize()),"buyer_image":hex::encode(owners[0].image.to_bytes()),
        "key_images":original.iter().map(|i|hex::encode(i.to_bytes())).collect::<Vec<_>>(),"pseudo_masks":masks});
    let unsigned = hex::encode(body.serialize());
    let mut states = owners.drain(..).map(|o| {
        let joint = accept(&o,&package,&unsigned,&policy).unwrap();
        State {own:Some(o), joint:Some(joint), ..State::default()}
    }).collect::<Vec<_>>();
    let bind = json!({"command":"joint_bind","message":hex::encode(vec![0x43;1006])});
    let mut rpc = None;
    for state in &mut states { handle(&bind,state,&mut rpc).await.unwrap(); }
    let buyer = handle(&json!({"command":"joint_sign"}),&mut states[0],&mut rpc).await.unwrap();
    let mut signatures = vec![buyer.clone()];
    for state in &mut states[1..] {
        signatures.push(handle(&json!({"command":"joint_sign","prior_contribution":buyer}),state,&mut rpc).await.unwrap());
    }
    let joint = states[5].joint.as_ref().unwrap();
    assert!(assemble(joint,&signatures[..5]).is_err());
    let mut duplicated = signatures.clone(); duplicated[5] = duplicated[4].clone();
    assert!(assemble(joint,&duplicated).is_err());
    let mut swapped = signatures.clone(); swapped.reverse();
    let assembled = assemble(joint,&swapped).unwrap();
    assert_eq!(assembled["verified_clsags"],6);
    assert_eq!(assembled["verified_balance"],true);
    assert_eq!(assembled["verified_bulletproof_plus"],true);
    assert_eq!(verify_native(joint,assembled["blob"].as_str().unwrap()).unwrap()["valid"],true);
    assert_eq!(chain_outputs(joint).unwrap().len(),96);
    let response = json!({"status":"OK", "outs":joint.inputs.iter().flat_map(|i|i.decoys().ring()).map(|r|
        json!({"key":hex::encode(r[0].compress().to_bytes()),"mask":hex::encode(r[1].compress().to_bytes()),"unlocked":true})).collect::<Vec<_>>()});
    assert!(match_chain_outputs(joint,&response).is_ok());
    let mut changed = response.clone(); changed["outs"][0]["key"] = json!(hex::encode(pubkey(Scalar::random(&mut OsRng)).compress().to_bytes()));
    assert!(match_chain_outputs(joint,&changed).is_err());
    changed = response.clone(); changed["outs"][0]["mask"] = json!(hex::encode(pubkey(Scalar::random(&mut OsRng)).compress().to_bytes()));
    assert!(match_chain_outputs(joint,&changed).is_err());
    changed = response.clone(); changed["outs"][0]["unlocked"] = json!(false);
    assert!(match_chain_outputs(joint,&changed).is_err());
    changed = response.clone(); changed["outs"].as_array_mut().unwrap().pop();
    assert!(match_chain_outputs(joint,&changed).is_err());
    changed = response.clone(); changed["untrusted"] = json!(true);
    assert!(match_chain_outputs(joint,&changed).is_err());
    let mut missing = package.clone(); missing["buyer_image"] = Value::Null;
    assert!(accept(states[1].own.as_ref().unwrap(),&missing,&unsigned,&policy).is_err());
    let mut wrong_buyer = package.clone(); wrong_buyer["buyer_image"] = json!(hex::encode(states[1].own.as_ref().unwrap().image.to_bytes()));
    assert!(accept(states[1].own.as_ref().unwrap(),&wrong_buyer,&unsigned,&policy).is_err());
}

#[tokio::test]
async fn independent_native_inputs_and_mutations() {
    let buyer = own("buyer", 2_000_000);
    let seller = own("seller", 1_000_000);
    assert_ne!(buyer.input.key(), seller.input.key());
    let policy = json!({"payments":[destination(Some(1_000_000)),destination(Some(100_000)),destination(Some(20_000))],
        "change":destination(None)});
    let intent = SignableTransaction::new(RctType::ClsagBulletproofPlus,Zeroizing::new([23;32]),
        vec![seller.input.clone(),buyer.input.clone()],payments(&policy).unwrap(),
        Change::fingerprintable(Some(address(&policy["change"]).unwrap())),vec![vec![0;180]],FeeRate::new(1,1).unwrap()).unwrap();
    let original_images = vec![seller.image,buyer.image];
    let (body,_,sum) = intent.clone().xtop_joint_context(original_images.clone()).unwrap();
    assert_eq!(body.prefix().outputs.len(),4);
    let sorted_images = images(&body).unwrap();
    let first = Scalar::random(&mut OsRng);
    let second = Scalar::from(sum.into()-first.into());
    let package = json!({"intent":hex::encode(intent.serialize()),
        "key_images":original_images.iter().map(|i|hex::encode(i.to_bytes())).collect::<Vec<_>>(),
        "pseudo_masks":[{"key_image":hex::encode(sorted_images[0].to_bytes()),"mask":encoded_scalar(first)},
            {"key_image":hex::encode(sorted_images[1].to_bytes()),"mask":encoded_scalar(second)}]});
    let unsigned = hex::encode(body.serialize());
    let buyer_joint = accept(&buyer,&package,&unsigned,&policy).unwrap();
    let seller_joint = accept(&seller,&package,&unsigned,&policy).unwrap();
    assert!(accept(&own("seller",1_000_000),&package,&unsigned,&policy).is_err());
    let mut wrong_policy = policy.clone(); wrong_policy["payments"][0]["amount"] = json!(900_000);
    assert!(accept(&seller,&package,&unsigned,&wrong_policy).is_err());
    let mut wrong_masks = package.clone(); wrong_masks["pseudo_masks"][0]["mask"] = json!(encoded_scalar(Scalar::ZERO));
    assert!(accept(&seller,&wrong_masks,&unsigned,&policy).is_err());
    let mut buyer_state = State { own:Some(buyer),joint:Some(buyer_joint), ..State::default() };
    let mut seller_state = State { own:Some(seller),joint:Some(seller_joint), ..State::default() };
    let bind = json!({"command":"joint_bind","message":hex::encode([0x42;180])});
    let mut rpc = None;
    let b = handle(&bind,&mut buyer_state,&mut rpc).await.unwrap();
    let s = handle(&bind,&mut seller_state,&mut rpc).await.unwrap();
    assert_eq!(b,s);
    assert!(handle(&bind,&mut buyer_state,&mut rpc).await.is_err());
    assert!(handle(&json!({"command":"joint_sign"}),&mut seller_state,&mut rpc).await.is_err());
    let buyer_sig = handle(&json!({"command":"joint_sign"}),&mut buyer_state,&mut rpc).await.unwrap();
    let mut altered = buyer_sig.clone(); altered["signature_hash"] = json!(hex::encode([0;32]));
    assert!(handle(&json!({"command":"joint_sign","prior_contribution":altered}),&mut seller_state,&mut rpc).await.is_err());
    assert!(seller_state.joint.as_ref().unwrap().signed.is_none());
    let seller_sig = handle(&json!({"command":"joint_sign","prior_contribution":buyer_sig}),&mut seller_state,&mut rpc).await.unwrap();
    assert!(handle(&json!({"command":"joint_sign"}),&mut buyer_state,&mut rpc).await.is_err());
    let assembled = handle(&json!({"command":"joint_assemble","contributions":[buyer_sig,seller_sig]}),&mut buyer_state,&mut rpc).await.unwrap();
    let verified = handle(&json!({"command":"joint_verify","blob":assembled["blob"]}),&mut seller_state,&mut rpc).await.unwrap();
    assert_eq!(verified["valid"],true);
    let raw = hex::decode(assembled["blob"].as_str().unwrap()).unwrap();
    let tx = Transaction::read(&mut raw.as_slice()).unwrap();
    let mut changed_extra = tx.clone(); changed_extra.prefix_mut().extra[5] ^= 1;
    assert!(verify_native(seller_state.joint.as_ref().unwrap(),&hex::encode(changed_extra.serialize())).is_err());
    let mut changed_output = tx.clone(); changed_output.prefix_mut().outputs[0].key = pubkey(Scalar::random(&mut OsRng)).compress();
    assert!(verify_native(seller_state.joint.as_ref().unwrap(),&hex::encode(changed_output.serialize())).is_err());
    let changed_hash = changed_extra.signature_hash().unwrap();
    let joint = buyer_state.joint.as_ref().unwrap();
    if let Transaction::V2 { proofs:Some(RctProofs { prunable:RctPrunable::Clsag { clsags,pseudo_outs,.. },.. }),.. } = tx {
        for i in 0..2 {
            assert!(clsags[i].verify(joint.inputs[i].decoys().ring().iter().map(|r|[r[0].compress(),r[1].compress()]).collect(),
                &sorted_images[i],&pseudo_outs[i],&changed_hash).is_err());
        }
    } else { panic!("Expected native CLSAG transaction"); }
    let mut tampered_sig = buyer_sig.clone();
    let mut signature = hex::decode(tampered_sig["clsag"].as_str().unwrap()).unwrap(); signature[0] ^= 1;
    tampered_sig["clsag"] = json!(hex::encode(signature));
    assert!(assemble(joint,&[tampered_sig,seller_sig.clone()]).is_err());
    assert!(assemble(joint,&[buyer_sig.clone(),buyer_sig]).is_err());
    assert_eq!(assembled["verified_clsags"],2);
    assert_eq!(assembled["verified_balance"],true);
    assert_eq!(assembled["verified_bulletproof_plus"],true);
}
