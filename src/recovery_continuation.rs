use bc_components::PublicKeyBase;
use bc_envelope::prelude::*;
use anyhow::{Error, Result};

#[derive(Clone, Debug)]
pub struct RecoveryContinuation {
    pub old_key: PublicKeyBase,
    pub new_key: PublicKeyBase,
    pub expiry: dcbor::Date,
}

impl RecoveryContinuation {
    const NEW_KEY_PARAM: &'static Parameter = &Parameter::new_static_named("newKey");
    const EXPIRY_PARAM: &'static Parameter = &Parameter::new_static_named("expiry");

    pub fn new(old_key: PublicKeyBase, new_key: PublicKeyBase, expiry: dcbor::Date) -> Self {
        Self {
            old_key,
            new_key,
            expiry,
        }
    }

    pub fn old_key(&self) -> &PublicKeyBase {
        &self.old_key
    }

    pub fn new_key(&self) -> &PublicKeyBase {
        &self.new_key
    }

    pub fn expiry(&self) -> &dcbor::Date {
        &self.expiry
    }
}

impl From<RecoveryContinuation> for Envelope {
    fn from(request: RecoveryContinuation) -> Self {
        Envelope::new(request.old_key)
            .add_parameter(RecoveryContinuation::NEW_KEY_PARAM, request.new_key)
            .add_parameter(RecoveryContinuation::EXPIRY_PARAM, request.expiry)
    }
}

impl TryFrom<Envelope> for RecoveryContinuation {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        let old_key: PublicKeyBase = envelope.extract_subject()?;
        let new_key: PublicKeyBase = envelope.extract_object_for_parameter(Self::NEW_KEY_PARAM)?;
        let expiry: dcbor::Date = envelope.extract_object_for_parameter(Self::EXPIRY_PARAM)?;
        Ok(Self::new(old_key, new_key, expiry))
    }
}
