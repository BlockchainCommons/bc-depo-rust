use anyhow::{Error, Result};
use bc_components::XID;
use bc_envelope::prelude::*;
use bc_xid::XIDDocument;

#[derive(Clone, Debug)]
pub struct RecoveryContinuation {
    pub user_id: XID,
    pub new_xid_document: XIDDocument,
    pub expiry: Date,
}

impl RecoveryContinuation {
    const NEW_XID_DOCUMENT: &'static str = "newXIDDocument";
    const EXPIRY: &'static str = "expiry";

    pub fn new(
        user_id: XID,
        new_xid_document: XIDDocument,
        expiry: Date,
    ) -> Self {
        Self { user_id, new_xid_document, expiry }
    }

    pub fn user_id(&self) -> XID { self.user_id }

    pub fn new_xid_document(&self) -> &XIDDocument { &self.new_xid_document }

    pub fn expiry(&self) -> &Date { &self.expiry }
}

impl From<RecoveryContinuation> for Envelope {
    fn from(request: RecoveryContinuation) -> Self {
        Envelope::new(request.user_id)
            .add_assertion(
                RecoveryContinuation::NEW_XID_DOCUMENT,
                request.new_xid_document,
            )
            .add_assertion(RecoveryContinuation::EXPIRY, request.expiry)
    }
}

impl TryFrom<Envelope> for RecoveryContinuation {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self> {
        let user_id: XID = envelope.extract_subject()?;
        let xid_document_envelope = envelope
            .object_for_predicate(RecoveryContinuation::NEW_XID_DOCUMENT)?;
        let new_key = XIDDocument::try_from(xid_document_envelope)?;
        let expiry: Date = envelope
            .extract_object_for_predicate(RecoveryContinuation::EXPIRY)?;
        Ok(Self::new(user_id, new_key, expiry))
    }
}
