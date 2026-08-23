//! serde helpers for the JS boundary.
//!
//! `#[serde(default)]` handles a missing key, but JavaScript routinely sends
//! `{ witness: undefined }`, and serde_wasm_bindgen presents that as a
//! present value of an unreadable type. `Option<T>` already tolerates it;
//! collections do not. These deserializers treat null/undefined as empty.

use serde::{Deserialize, Deserializer};

pub fn vec_or_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}
