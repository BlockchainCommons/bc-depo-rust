use bc_components::{XID, XIDProvider};
use bc_xid::XIDDocument;

#[derive(Debug, Clone)]
pub struct User {
    xid_document: XIDDocument,
    recovery: Option<String>,
}

impl User {
    pub fn new(xid_document: impl AsRef<XIDDocument>) -> Self {
        Self::new_opt(xid_document.as_ref(), None)
    }

    pub fn new_opt(
        xid_document: impl AsRef<XIDDocument>,
        recovery: Option<String>,
    ) -> Self {
        Self {
            xid_document: xid_document.as_ref().clone(),
            recovery,
        }
    }

    pub fn user_id(&self) -> XID { self.xid_document.xid() }

    pub fn xid_document(&self) -> &XIDDocument { &self.xid_document }

    pub fn set_xid_document(&mut self, xid_document: impl AsRef<XIDDocument>) {
        self.xid_document = xid_document.as_ref().clone();
    }

    pub fn recovery(&self) -> Option<&str> { self.recovery.as_deref() }

    pub fn set_recovery(&mut self, recovery: Option<&str>) {
        self.recovery = recovery.map(str::to_owned);
    }
}
