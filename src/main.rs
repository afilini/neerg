#[macro_use]
extern crate lazy_static;

use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;

use bip0039::{Language, Mnemonic, Seed};

use magical_bitcoin_wallet::bitcoin;
use magical_bitcoin_wallet::electrum_client::Client as ElectrumClient;
use magical_bitcoin_wallet::sled;
use magical_bitcoin_wallet::{FeeRate, TxBuilder};

use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::{Network, Txid};

use magical_bitcoin_wallet::blockchain::ElectrumBlockchain;

mod descriptor;
mod ga;
mod subaccount;
mod types;

use ga::GAClient;
use subaccount::Subaccount;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let mut runtime = tokio::runtime::Builder::new()
        .threaded_scheduler()
        .core_threads(4)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async { async_main().await })
}

async fn async_main() -> Result<(), Box<dyn Error>> {
    let mnemonic_bip39 = Mnemonic::from_phrase("rabbit okay wrestle addict barrel tribe cricket cradle web flavor harbor hour mammal earth else silly prefer mimic visa drill prison film wait vendor", Language::English)?;
    let seed = Seed::new(&mnemonic_bip39, "");
    let seed_bytes: &[u8] = seed.as_bytes();
    let xprv = ExtendedPrivKey::new_master(Network::Testnet, seed_bytes)?;

    let session = Arc::new(GAClient::new(&xprv).await?);

    let electrum_client = Arc::new(ElectrumBlockchain::from(
        ElectrumClient::new("ssl://electrum.blockstream.info:60002", None).unwrap(),
    ));
    let database = Arc::new(sled::open("magical-db")?);

    let subaccount = Subaccount::new(
        &xprv,
        session.get_gait_path(),
        0,
        &database,
        &electrum_client,
        &session,
    )?;
    subaccount.sync(None)?;

    println!("balance: {}", subaccount.get_balance()?);

    let (psbt, details) = subaccount.create_tx(
        TxBuilder::from_addressees(vec![(subaccount.get_new_address()?, 0)])
            .enable_rbf()
            .send_all(),
    )?;
    // let (psbt, details) = subaccount.bump_fee(&Txid::from_str("dcc797d8af3fc267d198236fcdca17bf32323bf4f3e421a9c1b9992d76d319b8").unwrap(), TxBuilder::new().send_all().enable_rbf().fee_rate(FeeRate::from_sat_per_vb(2.5)))?;
    let (psbt, finalized) = subaccount.sign(psbt, None)?;
    println!("finalized = {}", finalized);

    let txid = subaccount.broadcast(psbt.extract_tx())?;
    println!("https://blockstream.info/testnet/tx/{}", txid);

    Ok(())
}
