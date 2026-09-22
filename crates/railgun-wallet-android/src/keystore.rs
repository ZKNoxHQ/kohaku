//! Mnemonic at rest.
//!
//! UNIMPLEMENTED. The shape is here so the front and the IPC surface are settled; the crypto is
//! deliberately absent rather than approximated, see ADR-026 and the plan in README.md.
//!
//! Target: the phrase is sealed with an AES-GCM key generated inside Android Keystore
//! (`setUserAuthenticationRequired(true)`, StrongBox when the device has it), so the key never
//! reaches this process and a biometric prompt gates every unseal. Rust holds the ciphertext
//! only. The Kotlin side is a small Tauri plugin; `tauri-plugin-biometric` gates the call,
//! it does not do the sealing.
//!
//! Until that plugin exists these three commands return an error and the front falls back on
//! typing the phrase at every unlock, which is what the desktop daemon does today.

use tauri::command;

const UNIMPLEMENTED: &str = "keystore not wired yet: type the phrase to unlock";

#[command]
pub async fn store_mnemonic(_phrase: String) -> Result<(), String> {
    Err(UNIMPLEMENTED.into())
}

#[command]
pub async fn load_mnemonic() -> Result<String, String> {
    Err(UNIMPLEMENTED.into())
}

#[command]
pub async fn forget_mnemonic() -> Result<(), String> {
    Err(UNIMPLEMENTED.into())
}
