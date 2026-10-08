use std::io::{self, Write};
use tokio::io::AsyncBufReadExt;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use monero_simple_request_rpc::{prelude::MoneroDaemon, SimpleRequestTransport};
use monero_wallet::{
    ed25519::{Scalar, Point, CompressedPoint}, address::{MoneroAddress, Network, AddressType},
    interface::prelude::*, ringct::RctType, send::{Change, SignableTransaction, TransactionKeys},
    Scanner, ViewPair, OutputWithDecoys, transaction::Timelock,
};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use zeroize::Zeroizing;
mod joint;

type Error = Box<dyn std::error::Error>;
type Rpc = MoneroDaemon<SimpleRequestTransport>;
fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, Error> {
    v[name].as_str().ok_or_else(|| format!("Missing {name}").into())
}
fn scalar(v: &Value, name: &str) -> Result<Scalar, Error> {
    let b = Zeroizing::new(hex::decode(field(v, name)?)?);
    if b.len() != 32 { return Err("Invalid scalar length".into()); }
    Ok(Scalar::read(&mut b.as_slice())?)
}
fn point(v: &Value, name: &str) -> Result<Point, Error> {
    let b = hex::decode(field(v, name)?)?;
    if b.len() != 32 { return Err("Invalid point length".into()); }
    Ok(CompressedPoint::read(&mut b.as_slice())?.decompress().ok_or("Invalid point")?)
}
fn pubkey(s: Scalar) -> Point { Point::from(s.into() * ED25519_BASEPOINT_POINT) }
async fn checked_rpc(v: &Value, cached: &mut Option<(String, Rpc)>) -> Result<Rpc, Error> {
    let url = field(v, "rpc")?;
    if cached.as_ref().map(|(current, _)| current.as_str()) != Some(url) {
        *cached = Some((url.to_owned(), SimpleRequestTransport::new(url.to_owned()).await?));
    }
    let rpc = cached.as_ref().ok_or("Missing RPC")?.1.clone();
    let info: Value = serde_json::from_str(&rpc.rpc_call("get_info", None, 16384).await?)?;
    if info["nettype"] != field(v, "network")? { return Err("Wrong network".into()); }
    Ok(rpc)
}
fn main() {
    std::thread::Builder::new().name("custody-signer".into()).stack_size(16 * 1024 * 1024)
        .spawn(|| tokio::runtime::Builder::new_current_thread().enable_all().build()
            .expect("runtime").block_on(command_loop())).expect("thread").join().expect("signer");
}
async fn command_loop() {
    let mut state = joint::State::default();
    let mut rpc = None;
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    loop {
        let mut line = Zeroizing::new(String::new());
        match reader.read_line(&mut line).await { Ok(0) | Err(_) => break, _ => () }
        if line.len() > 262144 { break; }
        let result = async {
            let v: Value = serde_json::from_str(&line)?;
            match field(&v, "command")? {
                "joint_input" | "joint_accept" | "joint_bind" | "joint_sign" | "joint_assemble" | "joint_verify" | "joint_check_inputs" =>
                    joint::handle(&v, &mut state, &mut rpc).await,
                _ => Err("Unsupported custody command".into())
            }
        }.await;
        rpc = None;
        let response = match result { Ok(v) => json!({"ok":v}), Err(_) => json!({"error":"signer_rejected"}) };
        println!("{response}");
        if io::stdout().flush().is_err() { break; }
    }
}
