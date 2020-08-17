use std::error::Error;
use std::ops::Deref;
use std::sync::Arc;

use magical_bitcoin_wallet::bitcoin;
use magical_bitcoin_wallet::sled;

use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;

use sled::{Db, Tree};

use magical_bitcoin_wallet::blockchain::ElectrumBlockchain;
use magical_bitcoin_wallet::types::ScriptType;
use magical_bitcoin_wallet::wallet::address_validator::AddressValidator;
use magical_bitcoin_wallet::wallet::signer::{Signer, SignerOrdering};
use magical_bitcoin_wallet::Wallet;

use crate::descriptor::get_descriptor;
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

        let (desc, service_fingerprint) =
            get_descriptor(xprv, gait_path, pointer, Network::Testnet);

        let mut wallet = Wallet::new(&desc, None, Network::Testnet, tree, Arc::clone(&client))?;

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
