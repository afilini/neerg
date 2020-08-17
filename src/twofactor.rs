use std::io::{stdin, stdout, Write};

use crate::types::TwoFactorMethod;

pub trait TwoFactorResolver: std::fmt::Debug + Send + Sync {
    fn get_method(&self, available: Vec<TwoFactorMethod>) -> TwoFactorMethod;
    fn get_code(&self) -> String;
}

#[derive(Debug)]
pub struct NoopResolver;

impl TwoFactorResolver for NoopResolver {
    fn get_method(&self, available: Vec<TwoFactorMethod>) -> TwoFactorMethod {
        unimplemented!()
    }

    fn get_code(&self) -> String {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct StdinResolver;

impl TwoFactorResolver for StdinResolver {
    fn get_method(&self, available: Vec<TwoFactorMethod>) -> TwoFactorMethod {
        loop {
            print!("Choose 2FA method among {:?}: ", available);
            stdout().flush().unwrap();

            let mut method = String::new();
            stdin().read_line(&mut method).unwrap();

            match method.to_lowercase().trim() {
                "gauth" => break TwoFactorMethod::Gauth,
                "email" => break TwoFactorMethod::Email,
                "phone" => break TwoFactorMethod::Phone,
                "sms" => break TwoFactorMethod::Sms,
                _ => continue,
            }
        }
    }

    fn get_code(&self) -> String {
        print!("Type your 2FA code: ");
        stdout().flush().unwrap();

        let mut code = String::new();
        stdin().read_line(&mut code).unwrap();

        code.trim().to_string()
    }
}
