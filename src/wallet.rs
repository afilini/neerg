use std::sync::Arc;

use crate::ga::GAClient;

pub struct GreenWallet {
    session: Arc<GAClient>,
}
