use super::socket_failure;
use std::io::{Error as IoError, ErrorKind};
use tokio_tungstenite::tungstenite::{Error, Message, error::ProtocolError};

#[test]
fn transport_diagnostics_distinguish_failure_categories_without_formatting_secrets() {
    let secret = "Bearer PRIVATE-token?path=/private/source";
    let errors = [
        (
            Error::Io(IoError::new(ErrorKind::ConnectionReset, secret)),
            "io-connection-reset",
        ),
        (
            Error::Io(IoError::new(ErrorKind::TimedOut, secret)),
            "io-timed-out",
        ),
        (Error::Io(IoError::other(secret)), "io-other"),
        (
            Error::Protocol(ProtocolError::ResetWithoutClosingHandshake),
            "protocol-reset-without-close",
        ),
        (Error::AlreadyClosed, "already-closed"),
        (Error::ConnectionClosed, "connection-closed"),
        (Error::Utf8(secret.to_owned()), "utf8"),
        (
            Error::WriteBufferFull(Box::new(Message::text(secret))),
            "write-buffer-full",
        ),
    ];
    for (error, category) in errors {
        for operation in ["send", "receive"] {
            let safe = socket_failure(operation, &error);
            assert_eq!(
                format!("{safe:#}"),
                format!("fleet {operation} failed ({category}); effects may exist")
            );
            assert!(
                safe.source().is_none(),
                "a chained raw error would leak through {{:#}}"
            );
            assert!(!format!("{safe:?}").contains(secret));
        }
    }
}

#[test]
fn handshake_response_body_and_headers_never_reach_transport_diagnostics() {
    let secret = "PRIVATE-response-token";
    let response = tokio_tungstenite::tungstenite::http::Response::builder()
        .status(401)
        .header("authorization", secret)
        .body(Some(secret.as_bytes().to_vec()))
        .unwrap();
    let safe = socket_failure("receive", &Error::Http(Box::new(response)));
    assert_eq!(
        format!("{safe:#}"),
        "fleet receive failed (http); effects may exist"
    );
    assert!(!format!("{safe:?}").contains(secret));
    assert!(safe.source().is_none());
}
