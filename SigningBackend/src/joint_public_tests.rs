use super::*;
use super::super::tests::{own, destination};
use monero_wallet::interface::FeeRate;

fn replace_context(owner: &mut OwnInput, decoys: Decoys, commitment: Commitment) {
    let mut bytes = Vec::new();
    owner.input.key().compress().write(&mut bytes).unwrap();
    owner.input.key_offset().write(&mut bytes).unwrap();
    commitment.write(&mut bytes).unwrap();
    decoys.write(&mut bytes).unwrap();
    owner.input = OutputWithDecoys::read(&mut bytes.as_slice()).unwrap();
}

fn pair(shared: bool) -> (OwnInput, OwnInput) {
    let mut buyer = own("buyer", 2_000_000);
    let mut seller = own("seller", 1_000_000);
    let mut shifted = seller.input.decoys().offsets().to_vec();
    shifted[0] = 100;
    let decoys = Decoys::new(shifted, 7, seller.input.decoys().ring().to_vec()).unwrap();
    let commitment = seller.input.commitment().clone();
    replace_context(&mut seller, decoys, commitment);
    if shared {
        let mut ring = public_descriptor(&buyer)["public_ring"].clone();
        ring["indices"][15] = json!(107);
        ring["members"][15] = json!({"key":hex::encode(seller.input.key().compress().to_bytes()),
            "commitment":hex::encode(seller.input.commitment().commit().compress().to_bytes())});
        let original_seller = public_descriptor(&seller)["public_ring"].clone();
        let seller_ring = json!({
            "indices": (1u64..=5).chain(100..=110).collect::<Vec<_>>(),
            "members":ring["members"].as_array().unwrap()[..5].iter().cloned()
                .chain(original_seller["members"].as_array().unwrap()[..11].iter().cloned()).collect::<Vec<_>>()});
        set_ring(&mut buyer, &ring).unwrap();
        set_ring(&mut seller, &seller_ring).unwrap();
    }
    (buyer, seller)
}

fn fixture(buyer: &OwnInput, seller: &OwnInput) -> (Joint, Value) {
    let policy = json!({"payments":[destination(Some(1_000_000)), destination(Some(100_000)), destination(Some(20_000))],
        "change":destination(None)});
    let intent = SignableTransaction::new(RctType::ClsagBulletproofPlus, Zeroizing::new([71;32]),
        vec![buyer.input.clone(), seller.input.clone()], payments(&policy).unwrap(),
        Change::fingerprintable(Some(address(&policy["change"]).unwrap())), vec![vec![0x47;180]], FeeRate::new(1,1).unwrap()).unwrap();
    let original = vec![buyer.image, seller.image];
    let (body, _, sum) = intent.clone().xtop_joint_context(original.clone()).unwrap();
    let seller_mask = Scalar::random(&mut OsRng);
    let buyer_mask = Scalar::from(sum.into() - seller_mask.into());
    let package = json!({"intent":hex::encode(intent.serialize()),"key_images":original.iter().map(|i|hex::encode(i.to_bytes())).collect::<Vec<_>>(),
        "buyer_image":hex::encode(buyer.image.to_bytes()),"pseudo_masks":[
            {"key_image":hex::encode(buyer.image.to_bytes()),"mask":encoded_scalar(buyer_mask)},
            {"key_image":hex::encode(seller.image.to_bytes()),"mask":encoded_scalar(seller_mask)}]});
    let mut joint = super::super::accept(buyer, &package, &hex::encode(body.serialize()), &policy).unwrap();
    joint.bound = true;
    let ring_record = |owner: &OwnInput| {
        let mut ring = public_descriptor(owner)["public_ring"].clone();
        ring["key_image"] = json!(hex::encode(owner.image.to_bytes()));
        ring
    };
    let request = json!({"unsigned_blob":hex::encode(body.serialize()),"buyer_image":hex::encode(buyer.image.to_bytes()),
        "own_pseudo_mask":encoded_scalar(seller_mask),"rings":[ring_record(buyer), ring_record(seller)]});
    (joint, request)
}

#[tokio::test]
async fn public_seller_signs_without_buyer_private_descriptor() {
    let (buyer, seller) = pair(true);
    let (mut buyer_joint, request) = fixture(&buyer, &seller);
    let mut seller_joint = accept_public(&seller, &request).unwrap();
    let buyer_signature = super::super::sign(&buyer, &mut buyer_joint, &json!({})).unwrap();
    let seller_signature = sign_public(&seller, &mut seller_joint, &json!({"prior_contribution":buyer_signature})).unwrap();
    let assembled = assemble_public(&seller_joint, &[seller_signature.clone(), buyer_signature.clone()]).unwrap();
    assert_eq!(assembled["policy_verified_by_backend"], false);
    assert_eq!(assembled["ring_chain_membership_verified_by_backend"], false);
    assert_eq!(assembled["verified_clsags"], 2);
    assert_eq!(assembled["shared_ring"], true);
    assert_eq!(assembled["shared_ring_members"], 6);
    assert_eq!(assembled["distinct_ring_members"], 26);
    assert_eq!(verify_native_public(&seller_joint, assembled["blob"].as_str().unwrap()).unwrap()["valid"], true);
    assert_eq!(super::super::verify_native(&buyer_joint, assembled["blob"].as_str().unwrap()).unwrap()["valid"], true);
    let stateless = json!({"command":"joint_check_public", "blob":assembled["blob"], "rings":request["rings"]});
    let checked = handle(&stateless, &mut State::default(), &mut None).await.unwrap();
    assert_eq!(checked["valid"], true);
    assert_eq!(checked["txid"], assembled["txid"]);
    let raw = hex::decode(assembled["blob"].as_str().unwrap()).unwrap();
    let mut mutated: Transaction = Transaction::read(&mut raw.as_slice()).unwrap();
    mutated.prefix_mut().extra[5] ^= 1;
    let mut corrupted = stateless.clone(); corrupted["blob"] = json!(hex::encode(mutated.serialize()));
    assert!(check_public(&corrupted).is_err());
    let mut raw_signature = raw.clone();
    let signature = hex::decode(buyer_signature["clsag"].as_str().unwrap()).unwrap();
    let signature_offset = raw_signature.windows(signature.len()).position(|w| w == signature).unwrap();
    raw_signature[signature_offset] ^= 1;
    corrupted["blob"] = json!(hex::encode(raw_signature));
    assert!(check_public(&corrupted).is_err());
    corrupted["blob"] = request["unsigned_blob"].clone();
    assert!(check_public(&corrupted).is_err());
    let mut bad_rings = stateless.clone(); bad_rings["rings"][0]["indices"][0] = json!(0);
    assert!(check_public(&bad_rings).is_err());
    assert!(sign_public(&seller, &mut seller_joint, &json!({"prior_contribution":buyer_signature})).is_err());
    assert!(assemble_public(&seller_joint, &[buyer_signature.clone(), buyer_signature.clone()]).is_err());
    assert!(assemble_public(&seller_joint, &[buyer_signature.clone()]).is_err());
    let descriptor = public_descriptor(&buyer);
    for name in ["descriptor", "amount", "input_key", "mask", "key_offset", "signer_index", "transaction_secret", "intent"] {
        assert!(descriptor.get(name).is_none());
        assert!(request.get(name).is_none());
    }
    let mut changed = seller_joint.body.clone();
    changed.prefix_mut().extra[5] ^= 1;
    let mut forged_body = request.clone(); forged_body["unsigned_blob"] = json!(hex::encode(changed.serialize()));
    let mut changed_joint = accept_public(&seller, &forged_body).unwrap();
    assert!(sign_public(&seller, &mut changed_joint, &json!({"prior_contribution":buyer_signature})).is_err());
    let mut wrong_mask = request.clone(); wrong_mask["own_pseudo_mask"] = json!(encoded_scalar(Scalar::random(&mut OsRng)));
    let mut wrong_joint = accept_public(&seller, &wrong_mask).unwrap();
    assert!(sign_public(&seller, &mut wrong_joint, &json!({"prior_contribution":buyer_signature})).is_err());
    assert!(wrong_joint.signed.is_none());
    let mut wrong_image = request.clone(); wrong_image["buyer_image"] = json!(hex::encode(seller.image.to_bytes()));
    assert!(accept_public(&seller, &wrong_image).is_err());
    let mut wrong_ring = request.clone(); wrong_ring["rings"][0]["indices"][0] = json!(0);
    assert!(accept_public(&seller, &wrong_ring).is_err());
    let mut independent = request.clone(); independent["rings"][0]["members"][0]["key"] = json!(hex::encode(pubkey(Scalar::random(&mut OsRng)).compress().to_bytes()));
    assert!(accept_public(&seller, &independent).is_err());
    let mut duplicate = request.clone(); duplicate["rings"][0]["members"][0] = duplicate["rings"][0]["members"][1].clone();
    assert!(accept_public(&seller, &duplicate).is_err());
    let mut malformed = request.clone(); malformed["unsigned_blob"] = json!(format!("{}00", request["unsigned_blob"].as_str().unwrap()));
    assert!(accept_public(&seller, &malformed).is_err());
    let mut raw = hex::decode(request["unsigned_blob"].as_str().unwrap()).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    malformed["unsigned_blob"] = json!(hex::encode(raw));
    assert!(accept_public(&seller, &malformed).is_err());
    let mut tampered = buyer_signature.clone();
    let mut signature = hex::decode(tampered["clsag"].as_str().unwrap()).unwrap(); signature[0] ^= 1;
    tampered["clsag"] = json!(hex::encode(signature));
    assert!(assemble_public(&seller_joint, &[tampered, seller_signature]).is_err());
    let mut state = State {own:Some(seller), public:Some(seller_joint), ..State::default()};
    assert!(handle(&json!({"command":"joint_set_ring"}), &mut state, &mut None).await.is_err());
    assert!(handle(&json!({"command":"joint_accept_public"}), &mut state, &mut None).await.is_err());
}

#[test]
fn shared_ring_prevents_seller_commitment_replacement_with_unchanged_buyer_clsag() {
    for shared in [false, true] {
        let (buyer, mut seller) = pair(shared);
        let (mut buyer_joint, request) = fixture(&buyer, &seller);
        let buyer_signature = super::super::sign(&buyer, &mut buyer_joint, &json!({})).unwrap();
        let hash = buyer_joint.body.signature_hash().unwrap();
        let seller_mask = scalar(&request, "own_pseudo_mask").unwrap();
        let new_commitment = Commitment::new(Scalar::random(&mut OsRng), seller.input.commitment().amount);
        let old_ring = seller.input.decoys();
        let signer = usize::from(old_ring.signer_index());
        let mut changed_ring = old_ring.ring().to_vec();
        changed_ring[signer][1] = new_commitment.commit();
        let new_decoys = Decoys::new(old_ring.offsets().to_vec(), old_ring.signer_index(), changed_ring.clone()).unwrap();
        replace_context(&mut seller, new_decoys, new_commitment);
        let (seller_signature, seller_pseudo) = Clsag::sign(&mut OsRng, vec![(seller.key.clone(),
            ClsagContext::new(seller.input.decoys().clone(), seller.input.commitment().clone()).unwrap())], seller_mask, hash).unwrap().pop().unwrap();
        seller_signature.verify(changed_ring.iter().map(|m|[m[0].compress(),m[1].compress()]).collect(),
            &seller.image, &seller_pseudo.compress(), &hash).unwrap();
        let bytes = hex::decode(buyer_signature["clsag"].as_str().unwrap()).unwrap();
        let unchanged_buyer = Clsag::read(16, &mut bytes.as_slice()).unwrap();
        let buyer_pseudo = strict_point(&buyer_signature, "pseudo_out").unwrap().compress();
        let mut buyer_ring = buyer.input.decoys().ring().to_vec();
        if shared {
            let source_index = seller.input.decoys().positions()[signer];
            let buyer_position = buyer.input.decoys().positions().iter().position(|i| *i == source_index).unwrap();
            buyer_ring[buyer_position][1] = seller.input.commitment().commit();
        }
        let buyer_still_verifies = unchanged_buyer.verify(buyer_ring.iter().map(|m|[m[0].compress(),m[1].compress()]).collect(),
            &buyer.image, &buyer_pseudo, &hash).is_ok();
        assert_eq!(buyer_still_verifies, !shared);
        verify_balance(&buyer_joint.body, &[buyer_pseudo, seller_pseudo.compress()]).unwrap();
        verify_rangeproof(&buyer_joint.body).unwrap();
        println!("shared_ring={shared}: replaced seller C + re-signed seller CLSAG, unchanged buyer verifies={buyer_still_verifies}");
    }
}
