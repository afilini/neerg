use std::error::Error;
use std::ops::Deref;
use std::sync::Arc;

use bdk::bitcoin;
use bdk::sled;

use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;

use sled::{Db, Tree};

use bdk::blockchain::ElectrumBlockchain;
use bdk::wallet::address_validator::AddressValidator;
use bdk::wallet::signer::{Signer, SignerOrdering};
use bdk::{ScriptType, Wallet};

use crate::descriptor::GreenSubaccountDescriptor;
use crate::ga::*;
use crate::twofactor::StdinResolver;
use crate::types::TwoFactorConfigResponse;

pub struct Subaccount {
    wallet: Wallet<Arc<ElectrumBlockchain>, Tree>,
}

impl Subaccount {
    pub fn new(
        xprv: &ExtendedPrivKey,
        gait_path: &Vec<u16>,
        pointer: u16,
        db: &Db,
        client: &Arc<ElectrumBlockchain>,
        session: &Arc<GAClient>,
        twofactor_config: TwoFactorConfigResponse,
    ) -> Result<Self, Box<dyn Error>> {
        let tree = db.open_tree(pointer.to_string())?;

        let pointer = match pointer {
            0 => None,
            p => Some(p),
        };

        let desc = GreenSubaccountDescriptor {
            xprv,
            gait_path,
            subaccount: pointer,
        };
        let service_fingerprint = desc.get_service_fingerprint(Network::Testnet);

        // let (desc, service_fingerprint) =
        //     get_descriptor(xprv, gait_path, pointer, Network::Testnet);

        let mut wallet = Wallet::new(desc, None, Network::Testnet, tree, Arc::clone(&client))?;

        let signer = Box::new(GASigner {
            session: Arc::clone(session),
            service_fingerprint,
            resolver: Arc::new(StdinResolver),
            twofactor_config,
        }) as Box<dyn Signer>;
        wallet.add_signer(
            ScriptType::External,
            service_fingerprint.into(),
            SignerOrdering(200),
            Arc::new(signer),
        );

        let address_validator = Box::new(GAAddressValidator {
            session: Arc::clone(session),
            subaccount: pointer.unwrap_or(0),
            service_fingerprint,
        }) as Box<dyn AddressValidator>;
        wallet.add_address_validator(Arc::new(address_validator));

        Ok(Subaccount { wallet })
    }
}

impl Deref for Subaccount {
    type Target = Wallet<Arc<ElectrumBlockchain>, Tree>;

    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}
