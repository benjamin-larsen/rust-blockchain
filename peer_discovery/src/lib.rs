use std::thread;
use std::sync::Arc;
pub use error::{Error, Result};

use tokio::runtime::Builder;
use utils::NodeConfig;
use crate::client::Client;

mod constants;
mod client;
mod error;
mod messages;
mod conn_man;

pub fn start_discovery(config: Arc<dyn NodeConfig>) {
    thread::spawn(move || {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();


        rt.block_on(async {
            let client = Client::new(config).await.expect("Failed to start client");

            client.start_net().await;
        });
    });
}