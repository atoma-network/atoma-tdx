use fastcrypto::{ed25519::Ed25519KeyPair, traits::{EncodeDecodeBase64, KeyPair}};
use serde::{Deserialize, Serialize};
use tdx::device::{Device, DeviceOptions};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeInfo {
    pub tdx_version: String,
    pub runtime_version: String,
    pub runtime_config: String,
    /// Runtime TCB measurements
    pub runtime_measurements: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestationData {
    pub quote: String,
    pub public_key: String,
    pub runtime_info: RuntimeInfo,
}

pub struct TeeKeyPair {
    key_pair: Ed25519KeyPair,
}

pub struct TeeAttestationClient {
    device: Device,
    key_pair: TeeKeyPair,
    runtime_info: RuntimeInfo,
}

impl TeeAttestationClient {
    /// Constructor
    pub fn new() -> Result<Self> {
        let key_pair = Ed25519KeyPair::generate(&mut rand::thread_rng());
        let device_options = DeviceOptions::default();
        Ok(Self {
            device: Device::new(device_options)?,
            key_pair: TeeKeyPair { key_pair },
            runtime_info: RuntimeInfo::new()?,
        })
    }

    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        let public_key = self.key_pair.key_pair.public().bytes();
        Ok(public_key)
    }
}

#[derive(Debug, Error)]
pub enum TeeAttestationClientError {
    #[error("TDX device error: {0}")]
    TdxDeviceError(#[from] tdx::device::DeviceError),
}
