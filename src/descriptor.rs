// From: https://github.com/afilini/gadescriptor

use std::ops::Deref;
use std::str::FromStr;

use bdk::bitcoin;

use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{ChainCode, ChildNumber, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use bitcoin::{Network, PublicKey};

lazy_static! {
    static ref GA_TESTNET: ExtendedPubKey = ExtendedPubKey {
        network: Network::Testnet,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key: PublicKey::from_str(
            "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3"
        )
        .unwrap(),
        chain_code: ChainCode::from_hex(
            "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04"
        )
        .unwrap(),
    };
    static ref GA_MAINNET: ExtendedPubKey = ExtendedPubKey {
        network: Network::Bitcoin,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key: PublicKey::from_str(
            "0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f"
        )
        .unwrap(),
        chain_code: ChainCode::from_hex(
            "e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d"
        )
        .unwrap(),
    };
}

fn derive_ga_xpub(
    gait_path: &Vec<u16>,
    subaccount: Option<u16>,
    ga_xpub: &ExtendedPubKey,
) -> ExtendedPubKey {
    let ctx = Secp256k1::new();

    let full_path = match subaccount {
        Some(subaccount) => {
            let mut path = vec![3];
            path.extend(gait_path);
            path.push(subaccount);

            path
        }
        None => {
            let mut path = vec![1];
            path.extend(gait_path);

            path
        }
    };
    let full_path: Vec<ChildNumber> = full_path
        .into_iter()
        .map(|index| ChildNumber::from_normal_idx(index.into()).unwrap())
        .collect();

    ga_xpub.derive_pub(&ctx, &full_path).unwrap()
}

pub fn get_descriptor(
    xprv: &ExtendedPrivKey,
    gait_path: &Vec<u16>,
    subaccount: Option<u16>,
    network: Network,
) -> (String, Fingerprint) {
    let service = match network {
        Network::Bitcoin => GA_MAINNET.deref(),
        Network::Testnet => GA_TESTNET.deref(),
        _ => unimplemented!(),
    };

    let derived_service_xpub = derive_ga_xpub(gait_path, subaccount, service);
    let service_fingerprint = derived_service_xpub.fingerprint();

    let extra_path = match subaccount {
        None => "".to_string(),
        Some(pointer) => format!("3'/{}'/", pointer),
    };

    let descriptor_str = format!(
        "sh(wsh(multi(2,{}/*,{}/{}1/*)))",
        derived_service_xpub, xprv, extra_path
    );

    (descriptor_str, service_fingerprint)
}
