// This example demonstrates how to create and manage multiple BDK wallets,
// persist them using bdk-sqlx with SQLite, sync them with a Testnet Electrum server,
// and simulate transaction creation (PSBTs) between these wallets.
//
// Purpose:
// - Show multi-wallet management within a single application.
// - Demonstrate PSBT creation and the signing process.
// - Illustrate usage of bdk-sqlx for SQLite persistence.
// - Show bdk-electrum for network interaction.
//
// How to run:
// 1. Ensure you have a Rust environment setup.
// 2. Execute: `cargo run --example three_wallets`
//
// Prerequisites:
// - Rust programming environment.
// - An internet connection is required to connect to the public Testnet Electrum server.
// - The example will create SQLite database files (e.g., `three_wallets_db_wallet1.sqlite`)
//   in the directory from which it is run. These files store wallet data.
//
// Note on Descriptors:
// The wallets use Taproot (tr()) descriptors with Testnet private keys (tprv).
// Taproot is a modern Bitcoin script type offering efficiency and privacy benefits.
// These specific `tprv`s are for demonstration and are not secure for real funds.

#![allow(unused)]
use std::collections::HashSet;
use std::io::Write;

use anyhow::anyhow;
use bdk_electrum::{electrum_client, BdkElectrumClient};
use bdk_sqlx::sqlx::Sqlite;
use bdk_sqlx::{SqliteStoreBuilder, Store};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::{FeeRate, KeychainKind, PersistedWallet, Wallet};
use rustls::crypto::ring::default_provider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

// Constants
const NETWORK: Network = Network::Testnet; // Using Bitcoin's Testnet
const ELECTRUM_URL: &str = "ssl://electrum.blockstream.info:60002"; // Public Testnet Electrum server
const DATABASE_URL_PREFIX: &str = "sqlite:three_wallets_db_"; // Prefix for SQLite database file names

// Wallet 1 Descriptors (Taproot, Testnet)
// These `tprv` (Testnet Private View) keys are for example purposes.
// The `tr()` wrapper indicates a Taproot descriptor.
// Derivation paths: m/86'/1'/0'/0/* for external (receive) and m/86'/1'/0'/1/* for internal (change)
const WALLET1_DESCRIPTOR_EXTERNAL: &str = "tr(tprv8ZgxMBicQksPeuVhWwi6wuMQkfZ67NEHFrvCgYkJY3J9T5T7XvD2n27sD1kXV6fn73zTYn7k21GjV8h2zSySB1YqX2xEUgBckQyKoTw7cmn/86'/1'/0'/0/*)";
const WALLET1_DESCRIPTOR_INTERNAL: &str = "tr(tprv8ZgxMBicQksPeuVhWwi6wuMQkfZ67NEHFrvCgYkJY3J9T5T7XvD2n27sD1kXV6fn73zTYn7k21GjV8h2zSySB1YqX2xEUgBckQyKoTw7cmn/86'/1'/0'/1/*)";

// Wallet 2 Descriptors (Taproot, Testnet)
const WALLET2_DESCRIPTOR_EXTERNAL: &str = "tr(tprv8ZgxMBicQksPdM2W1fQdStAxt2zYxVqLBeRBFPm2wMRcMmyDCJz9m4rXvYd2jXyFhgT1yEHzd1KkdEL8jY2hLVuPZ1wR2z1a3XGAbnyfC61/86'/1'/0'/0/*)";
const WALLET2_DESCRIPTOR_INTERNAL: &str = "tr(tprv8ZgxMBicQksPdM2W1fQdStAxt2zYxVqLBeRBFPm2wMRcMmyDCJz9m4rXvYd2jXyFhgT1yEHzd1KkdEL8jY2hLVuPZ1wR2z1a3XGAbnyfC61/86'/1'/0'/1/*)";

// Wallet 3 Descriptors (Taproot, Testnet)
const WALLET3_DESCRIPTOR_EXTERNAL: &str = "tr(tprv8ZgxMBicQksPefYAS9gV2ADbS4P2c13X77p9fXNBVq8g9gH7q52MdFzVbWvKQw27VDB72gSgSjdcjBArsXEYDbkHwzxhKkS2FpVaWqNPDY5/86'/1'/0'/0/*)";
const WALLET3_DESCRIPTOR_INTERNAL: &str = "tr(tprv8ZgxMBicQksPefYAS9gV2ADbS4P2c13X77p9fXNBVq8g9gH7q52MdFzVbWvKQw27VDB72gSgSjdcjBArsXEYDbkHwzxhKkS2FpVaWqNPDY5/86'/1'/0'/1/*)";

// Electrum client scan parameters
const STOP_GAP: usize = 20; // How many unused addresses to scan before stopping
const BATCH_SIZE: usize = 5; // How many script pubkeys to request at a time from Electrum

// Transaction simulation parameters
const DUMMY_SEND_AMOUNT: u64 = 1000; // sats
const DUMMY_FEE_RATE: f32 = 1.0; // sat/vb

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Installs the default Rustls crypto provider for TLS connections (e.g., to Electrum).
    default_provider()
        .install_default()
        .expect("Failed to install rustls default crypto provider");

    // Setup logging. RUST_LOG environment variable can override default filters.
    // Example: RUST_LOG="bdk_wallet=trace,three_wallets=trace" cargo run --example three_wallets
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| {
                "sqlx=warn,\
                 bdk_sqlx=info,\
                 bdk_wallet=info,\
                 three_wallets=debug" // Default log levels
                    .into()
            },
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    tracing::info!("Starting three_wallets example...");

    let secp = Secp256k1::new(); // Secp256k1 context for cryptographic operations

    // Create or load three distinct wallets.
    // Each wallet will have its own SQLite database file.
    let mut wallet1 = create_or_load_wallet("wallet1", WALLET1_DESCRIPTOR_EXTERNAL, WALLET1_DESCRIPTOR_INTERNAL, &secp).await?;
    let mut wallet2 = create_or_load_wallet("wallet2", WALLET2_DESCRIPTOR_EXTERNAL, WALLET2_DESCRIPTOR_INTERNAL, &secp).await?;
    let mut wallet3 = create_or_load_wallet("wallet3", WALLET3_DESCRIPTOR_EXTERNAL, WALLET3_DESCRIPTOR_INTERNAL, &secp).await?;

    tracing::info!("Wallet 1 ID (derived from descriptor): {}", wallet1.wallet_id());
    tracing::info!("Wallet 2 ID (derived from descriptor): {}", wallet2.wallet_id());
    tracing::info!("Wallet 3 ID (derived from descriptor): {}", wallet3.wallet_id());

    // Sync each wallet with the Electrum server to get its latest state (balance, UTXOs).
    // This step queries the blockchain (via Electrum) for the wallet's transaction history and UTXOs.
    sync_wallet(&mut wallet1, "Wallet 1").await?;
    sync_wallet(&mut wallet2, "Wallet 2").await?;
    sync_wallet(&mut wallet3, "Wallet 3").await?;

    tracing::info!("--- Simulating Transactions (PSBT Creation - No Broadcast) ---");
    tracing::info!("The following steps demonstrate creating Partially Signed Bitcoin Transactions (PSBTs).");
    tracing::info!("These transactions use dummy amounts ({} sats) and are NOT broadcast to the network.", DUMMY_SEND_AMOUNT);
    tracing::info!("Signing will likely fail or result in an unspendable transaction if the wallets have no real UTXOs (i.e., are not funded on Testnet).");
    tracing::info!("The primary purpose is to show the API flow for transaction building and signing.");

    // --- Wallet 1 sends to Wallet 2 ---
    tracing::info!("\nAttempting to create PSBT: Wallet 1 -> Wallet 2...");
    // Get a new address from Wallet 2 to send to.
    let addr_w2 = wallet2.reveal_next_address(KeychainKind::External);
    // Persist Wallet 2 to save the newly revealed address's index.
    wallet2.persist_async(wallet2.store_mut()).await?;
    tracing::info!("Wallet 2 new address for receiving: {} (index {})", addr_w2.address, addr_w2.index);
    
    let mut builder_w1_to_w2 = wallet1.build_tx();
    builder_w1_to_w2.add_recipient(addr_w2.address.script_pubkey(), DUMMY_SEND_AMOUNT);
    builder_w1_to_w2.fee_rate(FeeRate::from_sat_per_vb(DUMMY_FEE_RATE));

    match builder_w1_to_w2.finish() {
        Ok((mut psbt_w1_to_w2, details)) => {
            tracing::info!("PSBT created (Wallet 1 -> Wallet 2): Txid: {}, Total fees: {} sats", details.txid(), details.total_fees().unwrap_or(0));
            tracing::debug!("PSBT (Wallet 1 -> Wallet 2): {:?}", psbt_w1_to_w2);
            // Attempt to sign the PSBT. This requires UTXOs.
            match wallet1.sign(&mut psbt_w1_to_w2, Default::default()) {
                Ok(finalized) => tracing::info!("Wallet 1 signed PSBT (1->2). Finalized: {}", finalized),
                Err(e) => tracing::warn!("Failed to sign PSBT (Wallet 1 -> Wallet 2): {}. This is expected if wallet has no spendable UTXOs.", e),
            }
            tracing::info!("This PSBT (Wallet 1 -> Wallet 2), if signed and finalized with real funds, would be broadcast to the network.");
        }
        Err(e) => tracing::error!("Error building transaction (Wallet 1 -> Wallet 2): {}", e),
    }

    // --- Wallet 2 sends to Wallet 3 ---
    tracing::info!("\nAttempting to create PSBT: Wallet 2 -> Wallet 3...");
    let addr_w3 = wallet3.reveal_next_address(KeychainKind::External);
    wallet3.persist_async(wallet3.store_mut()).await?;
    tracing::info!("Wallet 3 new address for receiving: {} (index {})", addr_w3.address, addr_w3.index);

    let mut builder_w2_to_w3 = wallet2.build_tx();
    builder_w2_to_w3.add_recipient(addr_w3.address.script_pubkey(), DUMMY_SEND_AMOUNT);
    builder_w2_to_w3.fee_rate(FeeRate::from_sat_per_vb(DUMMY_FEE_RATE));

    match builder_w2_to_w3.finish() {
        Ok((mut psbt_w2_to_w3, details)) => {
            tracing::info!("PSBT created (Wallet 2 -> Wallet 3): Txid: {}, Total fees: {} sats", details.txid(), details.total_fees().unwrap_or(0));
            tracing::debug!("PSBT (Wallet 2 -> Wallet 3): {:?}", psbt_w2_to_w3);
            match wallet2.sign(&mut psbt_w2_to_w3, Default::default()) {
                Ok(finalized) => tracing::info!("Wallet 2 signed PSBT (2->3). Finalized: {}", finalized),
                Err(e) => tracing::warn!("Failed to sign PSBT (Wallet 2 -> Wallet 3): {}. This is expected if wallet has no spendable UTXOs.", e),
            }
            tracing::info!("This PSBT (Wallet 2 -> Wallet 3), if signed and finalized with real funds, would be broadcast to the network.");
        }
        Err(e) => tracing::error!("Error building transaction (Wallet 2 -> Wallet 3): {}", e),
    }

    // --- Wallet 3 sends to Wallet 1 ---
    tracing::info!("\nAttempting to create PSBT: Wallet 3 -> Wallet 1...");
    let addr_w1 = wallet1.reveal_next_address(KeychainKind::External);
    wallet1.persist_async(wallet1.store_mut()).await?;
    tracing::info!("Wallet 1 new address for receiving: {} (index {})", addr_w1.address, addr_w1.index);

    let mut builder_w3_to_w1 = wallet3.build_tx();
    builder_w3_to_w1.add_recipient(addr_w1.address.script_pubkey(), DUMMY_SEND_AMOUNT);
    builder_w3_to_w1.fee_rate(FeeRate::from_sat_per_vb(DUMMY_FEE_RATE));

    match builder_w3_to_w1.finish() {
        Ok((mut psbt_w3_to_w1, details)) => {
            tracing::info!("PSBT created (Wallet 3 -> Wallet 1): Txid: {}, Total fees: {} sats", details.txid(), details.total_fees().unwrap_or(0));
            tracing::debug!("PSBT (Wallet 3 -> Wallet 1): {:?}", psbt_w3_to_w1);
            match wallet3.sign(&mut psbt_w3_to_w1, Default::default()) {
                Ok(finalized) => tracing::info!("Wallet 3 signed PSBT (3->1). Finalized: {}", finalized),
                Err(e) => tracing::warn!("Failed to sign PSBT (Wallet 3 -> Wallet 1): {}. This is expected if wallet has no spendable UTXOs.", e),
            }
            tracing::info!("This PSBT (Wallet 3 -> Wallet 1), if signed and finalized with real funds, would be broadcast to the network.");
        }
        Err(e) => tracing::error!("Error building transaction (Wallet 3 -> Wallet 1): {}", e),
    }
    
    tracing::info!("\n--- End of Transaction Simulation ---");
    tracing::info!("To make this example spend real Testnet coins: ");
    tracing::info!("1. Fund one of the wallet's revealed addresses (e.g., from a Testnet faucet).");
    tracing::info!("2. Re-run the example. Syncing should show a balance.");
    tracing::info!("3. The PSBT creation for that wallet might then be signable.");
    tracing::info!("4. To actually broadcast, use `BdkElectrumClient::transaction_broadcast()` (not shown here).");

    Ok(())
}

/// Creates a new BDK wallet or loads it from the specified SQLite database if it already exists.
/// The wallet is configured with external (receive) and internal (change) Taproot descriptors.
async fn create_or_load_wallet<'a>(
    wallet_name_suffix: &str, // Used to construct a unique DB filename, e.g., "wallet1"
    external_desc: &'a str,   // External descriptor (tr(tprv/.../0/*))
    internal_desc: &'a str,   // Internal descriptor (tr(tprv/.../1/*))
    secp: &Secp256k1<bdk_wallet::bitcoin::secp256k1::All>,
) -> Result<PersistedWallet<Store<Sqlite>>, anyhow::Error> {
    // Wallet name derived from descriptors, used for identification within the store.
    let wallet_name_from_desc = match bdk_wallet::wallet_name_from_descriptor(
        external_desc,
        Some(internal_desc),
        NETWORK,
        secp,
    ) {
        Ok(name) => name,
        Err(e) => {
            // This should ideally not happen with valid tprvs.
            tracing::error!(
                "Critical: Failed to generate wallet name from descriptor for suffix '{}': {}. This might indicate an issue with descriptors.",
                wallet_name_suffix, e
            );
            // Fallback to ensure a name is still generated, though this indicates a problem.
            format!("error_name_{}", wallet_name_suffix)
        }
    };

    // Each wallet gets its own SQLite database file.
    let db_filename = format!("{}{}.sqlite", DATABASE_URL_PREFIX, wallet_name_suffix);
    tracing::info!("Wallet '{}' (suffix '{}') using database file: {}", wallet_name_from_desc, wallet_name_suffix, db_filename);

    // Configure the SQLite store for the wallet.
    let mut store = SqliteStoreBuilder::new()
        .wallet_name(wallet_name_from_desc.clone()) // Internal name for the store
        .network(NETWORK)
        .db_path(db_filename) // Path to the SQLite file
        .migrate(true)        // Apply database migrations automatically
        .build_store()
        .await?;

    // Attempt to load the wallet from the store. If it doesn't exist, create it.
    let mut wallet = match Wallet::load().load_wallet_async(&mut store).await? {
        Some(wallet) => {
            tracing::info!("Loaded existing wallet: {}", wallet_name_from_desc);
            wallet
        }
        None => {
            tracing::info!("No existing wallet found for '{}'. Creating new wallet...", wallet_name_from_desc);
            let new_wallet = Wallet::create(external_desc, internal_desc)
                .network(NETWORK)
                .create_wallet_async(&mut store)
                .await?;
            tracing::info!("Successfully created new wallet: {}", wallet_name_from_desc);
            new_wallet
        }
    };

    tracing::info!(
        "Wallet '{}' public descriptor (external): {:?}",
        wallet_name_from_desc,
        wallet.public_descriptor(KeychainKind::External).map(|d| d.to_string())
    );

    // Reveal an initial address and persist the wallet state.
    // This ensures the address index is correctly stored for new or loaded wallets.
    let external_addr_info = wallet.reveal_next_address(KeychainKind::External);
    tracing::info!(
        "Wallet '{}' current external address (index {}): {}",
        wallet_name_from_desc,
        external_addr_info.index,
        external_addr_info.address
    );

    wallet.persist_async(&mut store).await?;
    tracing::info!("Wallet '{}' state persisted successfully.", wallet_name_from_desc);

    Ok(wallet)
}

/// Syncs the given wallet with the blockchain via an Electrum server.
/// This process updates the wallet's transaction history, UTXOs, and balance.
async fn sync_wallet(
    wallet: &mut PersistedWallet<Store<Sqlite>>, // The wallet to sync
    wallet_name_str: &str,                       // A display name for logging
) -> anyhow::Result<()> {
    tracing::info!("\nAttempting to sync {} with Electrum server at {}...", wallet_name_str, ELECTRUM_URL);

    let client = BdkElectrumClient::new(
        electrum_client::Client::new(ELECTRUM_URL)
            .map_err(|e| anyhow!("Failed to create Electrum client for {}: {}", wallet_name_str, e))?
    );

    // Populate the Electrum client's transaction cache with transactions already known to the wallet.
    // This can reduce redundant downloads.
    client.populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));
    tracing::debug!("Transaction cache populated for {}", wallet_name_str);
    
    // Start a full scan to discover new transactions and UTXOs.
    // The `inspect` call provides progress logging during the scan.
    let request = wallet.start_full_scan().inspect({
        let mut stdout = std::io::stdout();
        let mut once = HashSet::<KeychainKind>::new();
        // This closure is called for each script pubkey being checked.
        move |keychain, spk_index, _| {
            if once.insert(keychain) { // Print keychain type only once
                print!("\nScanning keychain [{:?}] for {}:", keychain, wallet_name_str);
            }
            print!(" {:<3}", spk_index); // Print script pubkey index
            let _ = stdout.flush(); // Ensure progress is displayed immediately
        }
    });

    tracing::info!("Starting full scan for {} (Stop gap: {}, Batch size: {})...", wallet_name_str, STOP_GAP, BATCH_SIZE);
    let update = match client.full_scan(request, STOP_GAP, BATCH_SIZE, true) {
        Ok(update) => update,
        Err(e) => {
            return Err(anyhow!("Full scan failed for {}: {}. Check internet connection and Electrum server status.", wallet_name_str, e));
        }
    };
    println!(); // Newline after scan progress indicator

    // Apply the discovered updates to the wallet.
    wallet.apply_update(update)?;
    tracing::info!("Update applied for {}", wallet_name_str);

    // Persist the wallet's new state (updated transaction history, UTXOs, address indices) to the database.
    wallet.persist_async(wallet.store_mut()).await?;
    tracing::info!("{} synced and persisted successfully. Current balance: {} sats", 
        wallet_name_str, 
        wallet.balance().total().to_sat()
    );

    Ok(())
}
