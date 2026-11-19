//! EVM requests: the unsigned transaction a requester sends, the digest each leg signs, and the
//! signed result rebuilt from a signer's signature. Ported from keystore_module, which signed
//! these itself; here the account's signer signs the digest and the manager builds the result.

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{eip191_hash_message, Address, Bytes, Signature, TxKind, B256, U256};
use serde::Deserialize;

use crate::error::{bad, ManagerError, Result};

/// Fields of an unsigned transaction, as JSON from the caller. Numbers are hex (`0x…`) or decimal
/// strings to avoid precision loss across the JSON boundary. `fee_mode` picks EIP-1559 or legacy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedTx {
    pub to: Option<String>,
    /// Contract creation must be asked for: an absent `to` used to deploy and burn the value.
    #[serde(default)]
    pub create: bool,
    /// Present only so an access list is refused rather than silently dropped from what is signed.
    #[serde(default)]
    pub access_list: Option<serde_json::Value>,
    #[serde(default)]
    pub value: String,
    pub nonce: String,
    #[serde(default)]
    pub gas_limit: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub fee_mode: String,
    #[serde(default)]
    pub max_fee_per_gas: String,
    #[serde(default)]
    pub max_priority_fee_per_gas: String,
    #[serde(default)]
    pub gas_price: String,
}

pub fn parse_u128(s: &str, what: &str) -> Result<u128> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let v = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u128::from_str_radix(hex, 16),
        None => s.parse::<u128>(),
    };
    v.map_err(|e| bad(format!("{what}: {e}")))
}

/// Refused rather than truncated: `0x10000000000000005` must not sign as nonce 5.
fn parse_u64(s: &str, what: &str) -> Result<u64> {
    let wide = parse_u128(s, what)?;
    u64::try_from(wide).map_err(|_| bad(format!("{what}: {wide} does not fit in u64")))
}

fn parse_u256(s: &str, what: &str) -> Result<U256> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(U256::ZERO);
    }
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => U256::from_str_radix(hex, 16).map_err(|e| bad(format!("{what}: {e}"))),
        None => s.parse::<U256>().map_err(|e| bad(format!("{what}: {e}"))),
    }
}

/// With or without `0x`, any case; no EIP-55 checksum required.
pub fn parse_address(s: &str) -> Result<Address> {
    let t = s.trim();
    let hexpart = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    let bytes = hex::decode(hexpart).map_err(|e| ManagerError::InvalidParams(format!("{s}: {e}")))?;
    if bytes.len() != 20 {
        return Err(bad(format!("{s}: expected 20 bytes, got {}", bytes.len())));
    }
    Ok(Address::from_slice(&bytes))
}

fn parse_bytes(s: &str) -> Result<Bytes> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Bytes::new());
    }
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    Ok(Bytes::from(hex::decode(h).map_err(|e| bad(format!("data: {e}")))?))
}

pub fn parse_b256(s: &str) -> Result<B256> {
    let s = s.trim();
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(h).map_err(|e| bad(format!("digest hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(bad(format!("digest must be 32 bytes, got {}", bytes.len())));
    }
    Ok(B256::from_slice(&bytes))
}

/// Longest text signed: anything larger cannot be shown in full.
const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// Refuse text whose rendering can differ from its bytes: controls, bidirectional overrides and
/// zero-width characters let a display say one thing while the signature covers another.
pub fn check_displayable(text: &str, what: &str) -> Result<()> {
    if text.len() > MAX_MESSAGE_BYTES {
        return Err(bad(format!("{what}: {} bytes exceeds the {MAX_MESSAGE_BYTES}-byte limit", text.len())));
    }
    for c in text.chars() {
        let hidden = matches!(c,
            '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{7F}'..='\u{9F}'
            | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
            | '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}'
        );
        if hidden {
            return Err(bad(format!(
                "{what}: refusing U+{:04X} — it can render differently than it signs",
                c as u32
            )));
        }
    }
    Ok(())
}

/// A transaction leg read once, signed from that same reading.
pub enum ParsedTx {
    Legacy(TxLegacy),
    Eip1559(TxEip1559),
}

impl ParsedTx {
    pub fn parse(tx: &UnsignedTx, chain_id: u64) -> Result<Self> {
        let to = match (tx.to.as_deref().map(str::trim).filter(|s| !s.is_empty()), tx.create) {
            (Some(_), true) => return Err(bad("tx json: `to` and `create: true` are mutually exclusive")),
            (Some(s), false) => TxKind::Call(parse_address(s)?),
            (None, true) => TxKind::Create,
            (None, false) => return Err(bad("tx json: `to` is required; set `create: true` to deploy a contract")),
        };
        if tx.access_list.as_ref().is_some_and(|v| !v.is_null()) {
            return Err(bad(
                "tx json: access lists are not supported by this signer — remove `access_list` rather than have it \
                 silently dropped from the signed payload",
            ));
        }
        let (value, nonce, gas_limit, input) = (
            parse_u256(&tx.value, "value")?,
            parse_u64(&tx.nonce, "nonce")?,
            parse_u64(&tx.gas_limit, "gas_limit")?,
            parse_bytes(&tx.data)?,
        );
        match tx.fee_mode.trim() {
            "" | "eip1559" => Ok(ParsedTx::Eip1559(TxEip1559 {
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas: parse_u128(&tx.max_fee_per_gas, "max_fee_per_gas")?,
                max_priority_fee_per_gas: parse_u128(&tx.max_priority_fee_per_gas, "max_priority_fee_per_gas")?,
                to,
                value,
                input,
                access_list: Default::default(),
            })),
            "legacy" => Ok(ParsedTx::Legacy(TxLegacy {
                chain_id: Some(chain_id),
                nonce,
                gas_price: parse_u128(&tx.gas_price, "gas_price")?,
                gas_limit,
                to,
                value,
                input,
            })),
            other => Err(bad(format!("tx json: fee_mode must be \"eip1559\" or \"legacy\", got {other:?}"))),
        }
    }

    /// Where it goes (`None` deploys), what it sends, its data, and the most its gas can cost.
    pub fn call_parts(&self) -> (Option<Address>, U256, Bytes, u128) {
        let (to, value, input, gas, price) = match self {
            ParsedTx::Legacy(t) => (t.to, t.value, t.input.clone(), t.gas_limit, t.gas_price),
            ParsedTx::Eip1559(t) => (t.to, t.value, t.input.clone(), t.gas_limit, t.max_fee_per_gas),
        };
        let to = match to {
            TxKind::Call(a) => Some(a),
            TxKind::Create => None,
        };
        (to, value, input, u128::from(gas).saturating_mul(price))
    }

    pub fn signing_hash(&self) -> B256 {
        match self {
            ParsedTx::Legacy(t) => t.signature_hash(),
            ParsedTx::Eip1559(t) => t.signature_hash(),
        }
    }

    /// What a device with a screen is handed: the bytes whose keccak-256 is the signing hash.
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            ParsedTx::Legacy(t) => t.encode_for_signing(&mut out),
            ParsedTx::Eip1559(t) => t.encode_for_signing(&mut out),
        }
        out
    }

    /// The broadcast-ready EIP-2718 envelope, `0x`-hex.
    pub fn signed_hex(self, sig: Signature) -> String {
        let raw = match self {
            ParsedTx::Legacy(t) => TxEnvelope::Legacy(t.into_signed(sig)).encoded_2718(),
            ParsedTx::Eip1559(t) => TxEnvelope::Eip1559(t.into_signed(sig)).encoded_2718(),
        };
        format!("0x{}", hex::encode(raw))
    }
}

/// EIP-191 `personal_sign` digest of displayable text.
pub fn message_hash(text: &str) -> Result<B256> {
    check_displayable(text, "message")?;
    Ok(eip191_hash_message(text.as_bytes()))
}

/// The EIP-712 signing hash, by alloy's implementation of the standard. A document it cannot type
/// is refused before anything is rendered or committed to.
pub fn typed_data_signing_hash(v: &serde_json::Value) -> Result<B256> {
    check_typed_fields(v)?;
    let td: alloy::dyn_abi::TypedData =
        serde_json::from_value(v.clone()).map_err(|e| bad(format!("typed_data: {e}")))?;
    td.eip712_signing_hash().map_err(|e| bad(format!("typed_data: {e}")))
}

/// Exactly the declared fields, at every level: an undeclared one would be shown and signed by nobody.
fn check_typed_fields(v: &serde_json::Value) -> Result<()> {
    let types = v.get("types").and_then(|t| t.as_object()).ok_or_else(|| bad("typed_data: no types"))?;
    let primary = v.get("primaryType").and_then(|p| p.as_str()).ok_or_else(|| bad("typed_data: no primaryType"))?;
    let message = v.get("message").ok_or_else(|| bad("typed_data: no message"))?;
    fn walk(
        types: &serde_json::Map<String, serde_json::Value>,
        ty: &str,
        value: &serde_json::Value,
        depth: usize,
    ) -> Result<()> {
        if depth > 16 {
            return Err(bad("typed_data: nested deeper than 16 levels"));
        }
        if let Some(open) = ty.find('[') {
            let items = value.as_array().ok_or_else(|| bad(format!("typed_data: {ty}: not an array")))?;
            for item in items {
                walk(types, &ty[..open], item, depth + 1)?;
            }
            return Ok(());
        }
        let Some(fields) = types.get(ty).and_then(|f| f.as_array()) else {
            return Ok(());
        };
        let obj = value.as_object().ok_or_else(|| bad(format!("typed_data: {ty}: not an object")))?;
        let declared: Vec<(&str, &str)> =
            fields.iter().filter_map(|f| Some((f.get("name")?.as_str()?, f.get("type")?.as_str()?))).collect();
        for key in obj.keys() {
            if !declared.iter().any(|(n, _)| n == key) {
                return Err(bad(format!("typed_data: {ty} does not declare a field `{key}`")));
            }
        }
        for (name, fty) in declared {
            let inner = obj.get(name).ok_or_else(|| bad(format!("typed_data: {ty} is missing its field `{name}`")))?;
            walk(types, fty, inner, depth + 1)?;
        }
        Ok(())
    }
    walk(types, primary, message, 0)
}

/// A signer's answer as alloy's signature: `r‖s` and the recovery id.
pub fn signature(rs_hex: &str, recovery_id: Option<u8>) -> Result<Signature> {
    let rs = hex::decode(rs_hex).map_err(|e| ManagerError::Signing(format!("signature hex: {e}")))?;
    if rs.len() != 64 {
        return Err(ManagerError::Signing(format!("a signature is 64 bytes, got {}", rs.len())));
    }
    let id = recovery_id.ok_or_else(|| ManagerError::Signing("an EVM signature carries its recovery id".into()))?;
    Ok(Signature::new(U256::from_be_slice(&rs[..32]), U256::from_be_slice(&rs[32..]), id == 1))
}

/// 65 bytes `r‖s‖v`, `0x`-hex: what keystore_module returned for a message, digest or typed data.
pub fn signature_hex(sig: &Signature) -> String {
    format!("0x{}", hex::encode(sig.as_bytes()))
}
