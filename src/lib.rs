#![forbid(unsafe_code)]

//! Streams that arrive as rows. One row is one Stream: the last column of
//! a configured query is what Xmip carries, the first column is where it
//! came from.
//!
//! SQL Server is the database most of the estate's partners already have,
//! and a table in it is the oldest integration surface there is: a
//! producer inserts, an integrator polls. A Receive Location runs its
//! query — `SELECT id, payload FROM inbox ORDER BY id` unless told
//! otherwise — and hands each row up; a Send Location inserts the Stream
//! as one column of one row — as an `N'…'` literal when the Stream is
//! UTF-8 without a NUL, as a `0x…` binary literal otherwise, and a value
//! in that form is the bytes again on the way back (`binary.rs`). What is
//! spoken is Tabular Data Stream 7.4 on port 1433: pre-login, LOGIN7 with
//! SQL Server authentication, a SQL batch, the token stream back. Windows
//! and federated authentication are not implemented; a server that
//! requires encryption is told so, because TLS is the transport
//! capability's, per ADR-0033.
//!
//! Rows are artefacts and this transport claims none of them, per ADR-0024:
//! the atomic claim a database has, `WITH (UPDLOCK, READPAST)`, only holds
//! inside a transaction, and the flow here opens and closes its connection
//! inside one receive, so there is no transaction to hold it across the
//! Stream's lifetime. Until the claim is written, a Receive Location is
//! one consumer of its query, and the query itself — a status column, a
//! `DELETE … OUTPUT deleted.*` — is what keeps a row from arriving twice.
//!
//! The origin URI carries what the row knew: `mssql://server/orders?row=41`.
//! A send target is `mssql://host:1433/<database>/<table>/<column>`,
//! `host:1433/<database>/<table>/<column>`, or `<table>/<column>` on the
//! configured server and database.

pub mod batch;
pub mod binary;
pub mod client;
pub mod column;
pub mod insert;
pub mod login;
pub mod prelogin;
pub mod session;
pub mod token;
pub mod wire;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, QueryResult, quote_identifier, quote_literal};
pub use login::Login;
pub use session::{Answer, Event, Session};
use transport::claim::{NoNativeClaim, ResourceClaim};
use transport::error::{Result, TransportError, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;
use transport::{Arrived, Directions, Transport};

/// What a Receive Location runs unless told otherwise.
pub const DEFAULT_QUERY: &str = "SELECT id, payload FROM inbox ORDER BY id";

/// What the loopback pair agrees on: one database, one user whose login
/// the far end takes as it comes, one table and column the payload is
/// inserted into.
const LOOPBACK_DATABASE: &str = "probe";
const LOOPBACK_USER: &str = "xmip";
const LOOPBACK_TARGET: &str = "probe/payload";

#[derive(Clone)]
pub struct MssqlTransport {
    server: String,
    database: String,
    user: String,
    password: Option<String>,
    query: String,
    timeout: Option<Duration>,
}

impl MssqlTransport {
    /// Speak to the server at `server`, on `database`, as `user`.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        database: impl Into<String>,
        user: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            database: database.into(),
            user: user.into(),
            password: None,
            query: DEFAULT_QUERY.to_string(),
            timeout: None,
        }
    }

    /// The password the login carries; empty without one.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// The query a receive runs: the first column is the row's name, the
    /// last is the Stream.
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    /// Give up on a server that stops mid-message.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The login this transport gives.
    #[must_use]
    pub fn login(&self) -> Login {
        Login::new(&*self.user, self.password.clone().unwrap_or_default())
    }

    /// Log in to the server.
    ///
    /// # Errors
    /// Where the server could not be reached or refused the login.
    pub fn connect(&self) -> Result<Client> {
        self.connect_to(&self.server, &self.database)
    }

    fn connect_to(&self, server: &str, database: &str) -> Result<Client> {
        Client::connect(server, database, &self.login(), self.timeout)
    }

    /// Bind as the far end clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// Accept one client on an already-bound listener, demanding this
    /// transport's user and password where it has a password.
    ///
    /// # Errors
    /// Where the connection could not be accepted or the login failed.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        let expected = self.password.as_ref().map(|_| self.login());
        Session::accept(listener, expected.as_ref(), self.timeout)
    }

    /// Where a target names the server, database, table and column, or
    /// some suffix of them on what this transport is configured with.
    fn resolve<'a>(&'a self, target: &'a str) -> Result<(&'a str, &'a str, &'a str, &'a str)> {
        let (server, path) = socket::target("mssql", target)
            .or_else(|| socket::target("sqlserver", target))
            .or_else(|| match target.split_once('/') {
                Some((peer, path)) if peer.contains(':') => Some((peer, path)),
                _ => None,
            })
            .unwrap_or((&self.server, target));
        let segments: Vec<&str> = path.split('/').collect();
        match segments.as_slice() {
            [database, table, column] => Ok((server, database, table, column)),
            [table, column] => Ok((server, &self.database, table, column)),
            _ => Err(TransportError::permanent(format!(
                "{target:?} is not database/table/column or table/column"
            ))),
        }
    }
}

impl Transport for MssqlTransport {
    fn name(&self) -> &'static str {
        "mssql"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// Run the query; each row is a Stream.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let mut client = self.connect()?;
        let result = client.query(&self.query)?;
        client.close()?;
        let mut arrived = Vec::with_capacity(result.rows.len());
        for (index, row) in result.rows.into_iter().enumerate() {
            let name = row
                .first()
                .cloned()
                .flatten()
                .unwrap_or_else(|| index.to_string());
            let value = row.last().cloned().flatten().unwrap_or_default();
            arrived.push(Arrived::new(
                format!("mssql://{}/{}?row={name}", self.server, self.database),
                binary::column_bytes(value),
            ));
        }
        Ok(arrived)
    }

    /// Insert the bytes as one column of one row: text as text, anything
    /// else as a binary literal.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (server, database, table, column) = self.resolve(target)?;
        let literal = match std::str::from_utf8(bytes) {
            Ok(text) if binary::is_text(bytes) => quote_literal(text),
            _ => binary::hex_literal(bytes),
        };
        let mut client = self.connect_to(server, database)?;
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            quote_identifier(table),
            quote_identifier(column),
            literal
        );
        client.execute(&sql)?;
        client.close()
    }

    /// Rows are artefacts, and one batch holds no transaction to claim
    /// one in.
    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl MssqlTransport {
    /// Both ends on this machine: an ephemeral local port, a login the far
    /// end takes as it comes, the loopback timeout.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", LOOPBACK_DATABASE, LOOPBACK_USER)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound listener waiting for its one client: logged in, one INSERT
/// taken as the Stream, the close read.
struct Listening {
    transport: MssqlTransport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let mut session = self.transport.accept_one(&self.listener)?;
        let arrived = session
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))?;
        // Read the close that follows, so the client goes before the far
        // end does.
        session.next_insert()?;
        Ok(arrived)
    }
}

impl Loopback for MssqlTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening {
            transport: self.clone(),
            listener,
            address,
        }))
    }

    /// INSERT the payload as one column of one row — text as an `N'…'`
    /// literal, anything else as `0x…` — from a fresh near end logging in
    /// to `address` as this transport does.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = Self {
            server: address.to_string(),
            ..self.clone()
        };
        near.send(LOOPBACK_TARGET, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_receive_runs_the_query_and_each_row_is_a_stream() {
        let far_end =
            MssqlTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            MssqlTransport::new(address, "orders", "xmip")
                .with_query("SELECT id, kind, payload FROM inbox ORDER BY id")
                .timing_out_after(secs(2))
                .receive()
        });
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(
                &["id", "kind", "payload"],
                &[
                    &[Some("41"), Some("order"), Some("ISA*00*")],
                    &[None, Some("raw"), Some("0xfffe")],
                ],
            );
        assert_eq!(session.user(), "xmip");
        assert_eq!(session.database(), "orders");
        assert_eq!(session.login().hostname, "xmip");
        let event = session.next_event().expect("query").expect("one");
        assert_eq!(
            event,
            Event::Selected("SELECT id, kind, payload FROM inbox ORDER BY id".into())
        );
        assert!(session.next_event().expect("closed").is_none());
        let arrived = receiver.join().expect("thread").expect("receiving");
        assert_eq!(arrived.len(), 2);
        assert_eq!(arrived[0].bytes, b"ISA*00*");
        assert!(arrived[0].origin_uri.ends_with("/orders?row=41"));
        assert_eq!(
            arrived[1].bytes,
            [0xff, 0xfe],
            "a binary literal is the bytes"
        );
        assert!(arrived[1].origin_uri.ends_with("?row=1"), "named by index");
    }

    #[test]
    fn a_send_inserts_the_stream_as_one_column_and_the_login_is_checked() {
        let far_end = MssqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            let near = MssqlTransport::new(address.clone(), "orders", "xmip")
                .with_password("secret")
                .timing_out_after(secs(2));
            near.send(
                &format!("mssql://{address}/orders/inbox/payload"),
                b"it's here",
            )?;
            near.send("outbox/body", b"")?;
            near.send(&format!("{address}/orders/inbox/payload"), &[0xff, 0xfe])?;
            let bad_target = near.send("sqlserver://host/only-one", b"x");
            let refused = MssqlTransport::new(address, "orders", "xmip")
                .with_password("wrong")
                .timing_out_after(secs(2))
                .send("inbox/payload", b"x");
            Ok::<_, TransportError>((bad_target, refused))
        });
        let mut session = far_end.accept_one(&listener).expect("accepting");
        let first = session.next_insert().expect("first").expect("one");
        assert_eq!(first.bytes, b"it's here");
        assert!(first.origin_uri.ends_with("/orders/inbox/payload"));
        assert!(session.next_insert().expect("closed").is_none());
        let mut session = far_end.accept_one(&listener).expect("second");
        let second = session.next_insert().expect("second").expect("one");
        assert!(
            second.bytes.is_empty(),
            "an empty payload is an empty literal"
        );
        assert!(second.origin_uri.ends_with("/orders/outbox/body"));
        let mut session = far_end.accept_one(&listener).expect("third");
        let binary = session.next_insert().expect("third").expect("one");
        assert_eq!(
            binary.bytes,
            [0xff, 0xfe],
            "not text, so the binary literal"
        );
        let error = far_end.accept_one(&listener).err().expect("wrong password");
        assert!(error.message.contains("Login failed"));
        let (bad_target, refused) = sender.join().expect("thread").expect("sending");
        assert!(!bad_target.expect_err("not a column").retryable);
        let refused = refused.expect_err("wrong password");
        assert!(!refused.retryable);
        assert!(refused.message.contains("18456"), "{refused}");
        assert!(far_end.claims().is_some(), "rows are artefacts");
        assert_eq!(far_end.name(), "mssql");
        assert_eq!(far_end.directions(), Directions::BOTH);
    }

    #[test]
    fn a_batch_the_far_end_errors_is_the_senders_error() {
        let far_end =
            MssqlTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            MssqlTransport::new(address, "orders", "xmip")
                .timing_out_after(secs(2))
                .send("missing/payload", b"x")
        });
        let mut session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .answering(|sql| {
                sql.contains("[missing]").then(|| Answer::Error {
                    number: 208,
                    message: "Invalid object name 'missing'.".to_string(),
                })
            });
        let event = session.next_event().expect("batch").expect("one");
        assert!(matches!(event, Event::Executed(sql) if sql.starts_with("INSERT INTO [missing]")));
        let error = sender.join().expect("thread").expect_err("errored");
        assert!(error.message.contains("208"), "{error}");
        assert!(error.message.contains("Invalid object name"));
        assert!(!error.retryable);
    }

    #[test]
    fn the_loopback_inserts_text_and_bytes_through_its_own_session() {
        let pair = MssqlTransport::loopback();
        let arrived = pair.round(b"it's here").expect("round");
        assert_eq!(arrived.bytes, b"it's here");
        assert!(arrived.origin_uri.starts_with("mssql://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/probe/probe/payload"));
        let binary = pair.round(&[0xff, 0xfe]).expect("the binary literal");
        assert_eq!(binary.bytes, [0xff, 0xfe]);
        assert_eq!(pair.name(), "mssql");
        assert_eq!(pair.ceiling(), None);
    }

    /// The Playground's edge payloads, written here so the crate does not
    /// depend on it.
    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
        ]
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = MssqlTransport::loopback();
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }
}
