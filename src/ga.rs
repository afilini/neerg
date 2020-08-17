use std::error::Error;
use std::fmt;
use std::sync::{mpsc, Arc};

use wamp_async::{Arg, Client};

use magical_bitcoin_wallet::bitcoin;
use magical_bitcoin_wallet::descriptor::HDKeyPaths;
use magical_bitcoin_wallet::types::ScriptType;
use magical_bitcoin_wallet::wallet::address_validator::{AddressValidator, AddressValidatorError};
use magical_bitcoin_wallet::wallet::signer::{Signer, SignerError};

use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, Fingerprint};
use bitcoin::util::psbt;
use bitcoin::{Address, Network, Script, Transaction};

use crate::twofactor::*;
use crate::types::*;

pub struct GAClient {
    session: Client,
    auth_response: AuthenticateResponse,
}

impl GAClient {
    pub async fn new(xprv: &ExtendedPrivKey) -> Result<Self, Box<dyn Error>> {
        let (mut client, (evt_loop, _)) =
            Client::connect("wss://testwss.greenaddress.it/v2/ws/", None).await?;

        tokio::spawn(evt_loop);
        client.join_realm("realm1").await?;

        let secp = Secp256k1::signing_only();

        let master_pk = xprv.private_key.public_key(&secp);
        let master_address = Address::p2pkh(&master_pk, Network::Testnet);

        let (challenge, _) = client
            .call(
                "com.greenaddress.login.get_trezor_challenge",
                Some(vec![
                    Arg::String(master_address.to_string()),
                    Arg::Bool(true),
                ]),
                None,
            )
            .await?;

        let challenge = match &challenge.as_ref().unwrap()[0] {
            Arg::Uri(challenge) => {
                get_sign_message_hash(&("greenaddress.it      login ".to_owned() + challenge))
            }
            _ => unimplemented!(),
        };

        let sign_key = xprv
            .derive_priv(&secp, &[ChildNumber::from_normal_idx(0x4741b11e)?])?
            .private_key
            .key;
        let signature = secp.sign(&challenge, &sign_key).serialize_der();

        let (auth_response, _) = client
            .call(
                "com.greenaddress.login.authenticate",
                Some(vec![
                    Arg::String(signature.to_hex()),
                    Arg::Bool(false),
                    Arg::String("GA".into()),
                    Arg::String("my-device-id".into()),
                    Arg::String("[v2,sw]neerg".into()),
                ]),
                None,
            )
            .await?;

        let mut auth_response = serde_json::to_value(&auth_response)?;
        let auth_response: AuthenticateResponse = serde_json::from_value(auth_response[0].take())?;

        Ok(GAClient {
            session: client,
            auth_response,
        })
    }

    async fn call(&self, name: &str, args: Vec<Arg>) -> Result<serde_json::Value, Box<dyn Error>> {
        let (response, _) = self.session.call(name, Some(args), None).await?;

        Ok(serde_json::to_value(&response)?)
    }

    pub async fn vault_fund(&self, subaccount: u16) -> Result<VaultFundResponse, Box<dyn Error>> {
        let mut response = self
            .call(
                "com.greenaddress.vault.fund",
                vec![
                    Arg::Integer(subaccount as usize),
                    Arg::Bool(true),
                    Arg::String("p2wsh".into()),
                ],
            )
            .await?;
        Ok(serde_json::from_value(response[0].take())?)
    }

    pub async fn sign_raw_tx(
        &self,
        raw_tx: String,
        twofactor_data: TwoFactorData,
    ) -> Result<SignTxResponse, Box<dyn Error>> {
        let twofactor_data = serde_json::to_value(&twofactor_data)?;
        let twofactor_data = serde_json::from_value(twofactor_data)?;

        let mut response = self
            .call(
                "com.greenaddress.vault.sign_raw_tx",
                vec![Arg::String(raw_tx), twofactor_data],
            )
            .await?;
        Ok(serde_json::from_value(response[0].take())?)
    }

    pub async fn get_2fa_config(&self) -> Result<TwoFactorConfigResponse, Box<dyn Error>> {
        let mut response = self
            .call("com.greenaddress.twofactor.get_config", vec![])
            .await?;
        Ok(serde_json::from_value(response[0].take())?)
    }

    pub async fn request_2fa_code(
        &self,
        method: TwoFactorMethod,
        action: &str,
    ) -> Result<(), Box<dyn Error>> {
        if method == TwoFactorMethod::Gauth {
            return Ok(());
        }

        self.call(
            &format!("com.greenaddress.twofactor.request_{}", method.to_string()),
            vec![Arg::String(action.into())],
        )
        .await?;
        Ok(())
    }

    pub fn get_gait_path(&self) -> &Vec<u16> {
        &self.auth_response.gait_path
    }
}

#[derive(Debug)]
pub struct GASigner<R: TwoFactorResolver + 'static> {
    pub session: Arc<GAClient>,
    pub service_fingerprint: Fingerprint,
    pub resolver: Arc<R>,
    pub twofactor_config: TwoFactorConfigResponse,
}

impl<R: TwoFactorResolver> Signer for GASigner<R> {
    fn sign(
        &self,
        psbt: &mut psbt::PartiallySignedTransaction,
        input_index: usize,
    ) -> Result<(), SignerError> {
        if psbt.inputs[input_index].partial_sigs.contains_key(
            &psbt.inputs[input_index]
                .hd_keypaths
                .iter()
                .find(|(_, (fing, _))| fing == &self.service_fingerprint)
                .map(|(pk, _)| pk.clone())
                .unwrap(),
        ) {
            return Ok(());
        }

        let mut tx = psbt.clone().extract_tx();

        for (i, p_i) in tx.input.iter_mut().zip(psbt.inputs.iter()) {
            i.script_sig = Builder::new()
                .push_slice(&p_i.redeem_script.clone().unwrap().to_bytes())
                .into_script();

            if let Some(sig) = p_i.partial_sigs.values().nth(0) {
                i.witness = vec![sig.clone()];
            }
        }

        let session = Arc::clone(&self.session);
        let resolver = Arc::clone(&self.resolver);
        let twofactor_config = self.twofactor_config.clone();
        let (sender, receiver) = mpsc::channel();

        let handle = tokio::runtime::Handle::current();
        handle.spawn(async move {
            let method = resolver.get_method(twofactor_config.get_enabled());
            session
                .request_2fa_code(method, "send_raw_tx")
                .await
                .unwrap();
            let code = resolver.get_code();

            let twofactor_data = TwoFactorData { code, method };

            let result = session
                .sign_raw_tx(serialize_hex(&tx), twofactor_data)
                .await
                .map_err(|e| {
                    println!("{:?}", e);

                    SignerError::UserCanceled
                });
            sender.send(result).unwrap();
        });

        let signed_tx = receiver.recv().unwrap()?;
        let signed_tx: Transaction =
            deserialize(&Vec::<u8>::from_hex(&signed_tx.tx).unwrap()).unwrap();

        for p_i in &mut psbt.inputs {
            let service_pk = p_i
                .hd_keypaths
                .iter()
                .find(|(_, (fing, _))| fing == &self.service_fingerprint)
                .map(|(pk, _)| pk.clone())
                .unwrap();
            p_i.partial_sigs
                .insert(service_pk, signed_tx.input[input_index].witness[1].clone());
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct GAAddressValidator {
    pub session: Arc<GAClient>,
    pub service_fingerprint: Fingerprint,
    pub subaccount: u16,
}

impl AddressValidator for GAAddressValidator {
    fn validate(
        &self,
        _script_type: ScriptType,
        hd_keypaths: &HDKeyPaths,
        _script: &Script,
    ) -> Result<(), AddressValidatorError> {
        loop {
            let subaccount = self.subaccount;
            let session = Arc::clone(&self.session);

            let (sender, receiver) = mpsc::channel();
            let handle = tokio::runtime::Handle::current();
            handle.spawn(async move {
                let result = session
                    .vault_fund(subaccount)
                    .await
                    .map_err(|_| AddressValidatorError::ConnectionError);
                sender.send(result).unwrap();
            });

            let (_, path) = hd_keypaths
                .values()
                .find(|(fing, _)| fing == &self.service_fingerprint)
                .ok_or(AddressValidatorError::InvalidScript)?;

            let result = receiver.recv().unwrap()?;
            match path.as_ref()[0] {
                ChildNumber::Normal { index } if index <= result.pointer as u32 => {
                    return Ok(());
                }
                _ => continue,
            }
        }
    }
}

impl fmt::Debug for GAClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.auth_response)
    }
}

fn get_sign_message_hash(msg: &str) -> Message {
    let mut answer = b"\x18Bitcoin Signed Message:\n".to_vec();
    answer.push(msg.len() as u8);
    answer.extend_from_slice(msg.as_bytes());

    Message::from_slice(&sha256d::Hash::hash(&answer).into_inner()).unwrap()
}
