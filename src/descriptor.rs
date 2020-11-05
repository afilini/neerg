// From: https://github.com/afilini/gadescriptor

use std::ops::Deref;
use std::str::FromStr;

use bdk::bitcoin;
use bdk::descriptor::{Descriptor, KeyMap, ToWalletDescriptor};
use bdk::keys::KeyError;

use bdk::miniscript::descriptor::DescriptorPublicKey;

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

#[derive(Debug)]
pub struct GreenSubaccountDescriptor<'a> {
    pub xprv: &'a ExtendedPrivKey,
    pub gait_path: &'a Vec<u16>,
    pub subaccount: Option<u16>,
}

impl<'a> GreenSubaccountDescriptor<'a> {
    fn get_derived_service_xpub(&self, network: Network) -> ExtendedPubKey {
        let ctx = Secp256k1::new();

        let ga_xpub = match network {
            Network::Bitcoin => GA_MAINNET.deref(),
            Network::Testnet => GA_TESTNET.deref(),
            _ => unimplemented!(),
        };

        let full_path = match self.subaccount {
            Some(subaccount) => {
                let mut path = vec![3];
                path.extend(self.gait_path);
                path.push(subaccount);

                path
            }
            None => {
                let mut path = vec![1];
                path.extend(self.gait_path);

                path
            }
        };
        let full_path: Vec<ChildNumber> = full_path
            .into_iter()
            .map(|index| ChildNumber::from_normal_idx(index.into()).unwrap())
            .collect();

        ga_xpub.derive_pub(&ctx, &full_path).unwrap()
    }

    pub fn get_service_fingerprint(&self, network: Network) -> Fingerprint {
        self.get_derived_service_xpub(network).fingerprint()
    }
}

impl<'a> ToWalletDescriptor for GreenSubaccountDescriptor<'a> {
    fn to_wallet_descriptor(
        self,
        network: Network,
    ) -> Result<(Descriptor<DescriptorPublicKey>, KeyMap), KeyError> {
        let derived_service_xpub = self.get_derived_service_xpub(network);

        let mut path = match self.subaccount {
            None => vec![],
            Some(pointer) => vec![
                ChildNumber::Hardened { index: 3 },
                ChildNumber::Hardened {
                    index: pointer as u32,
                },
            ],
        };
        path.push(ChildNumber::Normal { index: 1 });

        let service_key = (derived_service_xpub, vec![].into());
        let user_key = (self.xprv.clone(), path.into());

        let descriptor = descriptor!(sh ( wsh ( multi 2, service_key, user_key ) ))?;
        Ok((descriptor.0, descriptor.1))
    }
}
