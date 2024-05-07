use bytes::Bytes;
use depo_api::StoreShareRequest;
use indoc::indoc;
use bc_components::{PrivateKeyBase, ARID};
use bc_envelope::prelude::*;

#[test]
fn test_depo_requests() {
    let id = ARID::from_data_ref(hex_literal::hex!(
        "8712dfac3d0ebfa910736b2a9ee39d4b68f64222a77bcc0074f3f5f1c9216d30"
    ))
    .unwrap();
    let private_key = PrivateKeyBase::new();
    let key = private_key.public_key();
    let data = Bytes::from_static(b"data");
    let request = StoreShareRequest::from_fields(id, key, data);
    assert_eq!(
        request.to_envelope().format(),
        indoc! {r#"
        request(ARID(8712dfac)) [
            'body': «"storeShare"» [
                ❰"data"❱: Bytes(4)
            ]
            'senderPublicKey': PublicKeyBase
        ]
        "#}
        .trim()
    );

    let server_private_key = PrivateKeyBase::new();
    let server_public_key = server_private_key.public_key();

    let encrypted_request = request
        .clone()
        .to_envelope()
        .seal(&private_key, &server_public_key)
        .unwrap();
    assert_eq!(
        encrypted_request.format(),
        indoc! {r#"
        ENCRYPTED [
            'hasRecipient': SealedMessage
        ]
        "#}
        .trim()
    );

    let signed_request = encrypted_request
        .decrypt_to_recipient(&server_private_key)
        .unwrap()
        .unwrap_envelope()
        .unwrap();
    assert_eq!(
        signed_request.format(),
        indoc! {r#"
        {
            request(ARID(8712dfac)) [
                'body': «"storeShare"» [
                    ❰"data"❱: Bytes(4)
                ]
                'senderPublicKey': PublicKeyBase
            ]
        } [
            'verifiedBy': Signature
        ]
        "#}
        .trim()
    );
}
