#![forbid(unsafe_code)]

//! Streams that arrive as rows. One row is one Stream: the last column of
//! a configured query is what Xmip carries, the first column is where it
//! came from.
//!
//! SQL Server is the database most of the estate's Parties already have,
//! and a table in it is the oldest integration surface there is: a
//! producer inserts, an integrator polls. A Receive Location runs its
//! query — `SELECT id, payload FROM inbox ORDER BY id` unless told
//! otherwise — and hands each row up; a Send Location inserts the Stream
//! as one column of one row. What the column holds is the Location's to
//! declare, never the bytes' (ADR-0038): `column = "binary"`, the default,
//! inserts every Stream as a `0x…` binary literal and reads a value back
//! from that form (T-SQL's, `xmip-core-library-sql`); `column = "text"` decodes the Stream
//! strictly in its `encoding` — `utf-8` unless another Unicode form is
//! named — inserts it as an `N'…'` literal, and encodes a value read back
//! to that form. A Stream that is not its declared form is refused, never
//! repaired; so is a row value that is not its column's encoding. What is
//! spoken is Tabular Data Stream 7.4 on port 1433: pre-login, LOGIN7 with
//! SQL Server authentication, a SQL batch, the token stream back. Windows
//! and federated authentication are not implemented; a server that
//! requires encryption is told so, because TLS is the transport
//! capability's, per ADR-0033.
//!
//! Rows are artifacts and this transport claims none of them, per ADR-0024:
//! the atomic claim a database has, `WITH (UPDLOCK, READPAST)`, only holds
//! inside a transaction, and the flow here opens and closes its connection
//! inside one receive, so there is no transaction to hold it across the
//! Stream's lifetime. Until the claim is written, a Receive Location is
//! one consumer of its query, and the query itself — a status column, a
//! `DELETE … OUTPUT deleted.*` — is what keeps a row from arriving twice.
//!
//! **A row is consumed by the `accept` statement, after its cycle.** The query
//! only reads. Where the Location declares `accept` — `DELETE FROM inbox WHERE
//! id = @P1` — it runs once a row's cycle accepted it, the row's name bound in
//! place of `@P1` (`transport::sql::accept`), written as T-SQL's string
//! literal (`N'…'`). A refused row is left where it lies, and not
//! received again while its body is unchanged. A row whose cycle failed is
//! left, and the next receive reads it again; so is a row whose name is NULL,
//! which no statement can name. Where `accept` is left out a row's verdict
//! tells the database nothing: every row is read again unless the query keeps
//! it from that. A query that consumes as it reads — a `DELETE … OUTPUT
//! deleted.*` — consumes before the receive cycle has run, so acceptance is
//! at-most-once under such a query.
//!
//! The origin URI carries what the row knew: `mssql://server/orders?row=41`.
//! A send target is `mssql://host:1433/<database>/<table>/<column>`,
//! `host:1433/<database>/<table>/<column>`, or `<table>/<column>` on the
//! configured server and database.
//!
//! **The transport is every SQL technology's**, `transport::sql`'s
//! `SqlTransport` over this crate's [`Mssql`] wire (2026-11-13): the query
//! and its rows, the `accept` statement after a row's cycle, the INSERT a
//! send writes, the connections kept per server and database, the
//! settings. What is SQL Server's own is this crate's: T-SQL, and the
//! Tabular Data Stream, both halves.

pub mod batch;
pub mod client;
pub mod column;
pub mod login;
pub mod prelogin;
pub mod session;
pub mod token;
pub mod wire;

use std::net::TcpListener;
use std::time::Duration;

pub use client::{Client, QueryResult};
pub use session::{Answer, Event, Session};
use sql::{Dialect, TSQL};
use transport::error::{Result, protocol_error};
use transport::sql::accept::ACCEPT;
use transport::sql::{
    COLUMN, DATABASE, ENCODING, Probe, QUERY, Rows, SqlTransport, TIMEOUT, USER, Wire,
};
use transport::{Login, Pooled, Taken};
use xcore::settings::Settings;

/// A Location over a SQL Server.
pub type MssqlTransport = SqlTransport<Mssql>;

/// SQL Server's wire: this crate's Tabular Data Stream client, logging in
/// with SQL Server authentication.
#[derive(Clone, Copy, Debug, Default)]
pub struct Mssql;

impl Wire for Mssql {
    type Client = Client;

    const NAME: &'static str = "mssql";
    const SCHEMES: &'static [&'static str] = &["mssql", "sqlserver"];
    /// The address is the server, `host:1433`, both sides log in to.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[DATABASE, USER, QUERY, ACCEPT, COLUMN, ENCODING, TIMEOUT],
    };
    /// One user whose login the far end takes as it comes.
    const PROBE: Probe = Probe {
        database: "probe",
        user: "xmip",
        password: "",
        target: "probe/payload",
    };

    fn dialect() -> &'static Dialect {
        &TSQL
    }

    fn connect(
        &self,
        server: &str,
        database: &str,
        login: &Login,
        timeout: Option<Duration>,
    ) -> Result<Client> {
        Client::connect(server, database, login, timeout)
    }

    fn usable(client: &mut Client) -> bool {
        client.usable()
    }

    fn query(client: &mut Client, sql: &str) -> Result<Rows<String>> {
        Ok(client.query(sql)?.rows)
    }

    fn execute(client: &mut Client, sql: &str) -> Result<()> {
        client.execute(sql).map(|_| ())
    }

    /// The client keeps its connection for the next insert.
    fn take_one(transport: &MssqlTransport, listener: &TcpListener) -> Result<Taken> {
        accept_one(transport, listener)?
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))
    }
}

/// Accept one client on a listener `transport` bound, demanding its user
/// and password where it has a password, the login taken as it comes where
/// it has none.
///
/// # Errors
/// Where the connection could not be accepted or the login failed.
pub fn accept_one(transport: &MssqlTransport, listener: &TcpListener) -> Result<Session> {
    let login = transport.login();
    let expected = (!login.password.is_empty()).then_some(login);
    Session::accept(listener, expected, transport.timeout())
        .map(|session| session.holding(transport.column()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::unicode::Form;
    use std::assert_matches;
    use transport::error::TransportError;
    use transport::payload::edge_payloads;
    use transport::sql::{Column, DEFAULT_QUERY};
    use transport::{Arrived, Configured, Directions, Loopback, Transport};
    use xcore::settings::Applies;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn mssql_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(MssqlTransport::SETTINGS.problems(), [] as [String; 0]);
        let given = [
            ("database".to_string(), Given::Text("orders".to_string())),
            ("user".to_string(), Given::Text("integration".to_string())),
            ("timeout".to_string(), Given::Text("30s".to_string())),
        ];
        let built = MssqlTransport::open("sql:1433", Applies::Receive, &given).expect("built");
        assert_eq!(built.server(), "sql:1433");
        assert_eq!(
            (built.database(), built.login().user.as_str()),
            ("orders", "integration")
        );
        assert_eq!(built.query(), DEFAULT_QUERY);
        assert_eq!(built.timeout(), Some(Duration::from_secs(30)));
        assert!(
            built.login().password.is_empty(),
            "the password is the secret's"
        );
        assert_eq!(built.column(), Column::Binary, "bytes unless declared");
        let mut texts = given.to_vec();
        texts.push(("column".to_string(), Given::Text("text".to_string())));
        texts.push(("encoding".to_string(), Given::Text("utf-32be".to_string())));
        let built = MssqlTransport::open("sql:1433", Applies::Send, &texts).expect("text");
        assert_eq!(built.column(), Column::Text(Form::Utf32Be));
        let Err(refused) = MssqlTransport::open("sql:1433", Applies::Send, &given[1..]) else {
            panic!("database is required");
        };
        assert!(refused.message.contains("\"database\""), "{refused}");
    }

    /// The first of `arrived` read and refused, the rest taken.
    fn verdicts(arrived: Vec<Arrived>) -> Result<Vec<Taken>> {
        let mut taken = Vec::new();
        for (index, one) in arrived.into_iter().enumerate() {
            assert!(one.defers());
            if index > 0 {
                taken.push(one.taken()?);
                continue;
            }
            let (origin, mut body, acknowledgement) = one.into_parts();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut body, &mut bytes).expect("reading");
            acknowledgement.acknowledge(transport::Verdict::Failed)?;
            taken.push(Taken::new(origin, bytes));
        }
        Ok(taken)
    }

    #[test]
    fn accept_consumes_an_accepted_row_and_a_refused_one_is_left_unreceived() {
        let far_end =
            MssqlTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = MssqlTransport::new(address, "orders", "xmip")
                .with_accept("DELETE FROM inbox WHERE id = @P1")
                .timing_out_after(secs(2));
            let mut arrived = near.receive()?;
            assert_eq!(arrived.len(), 4);
            arrived.remove(0).taken()?;
            arrived
                .remove(0)
                .refused(transport::Refusal::Unacceptable)?;
            arrived.remove(0).failed()?;
            arrived.remove(0).taken()?;
            let again: Vec<_> = near.receive()?.into_iter().map(|a| a.origin_uri).collect();
            assert_eq!(
                again.len(),
                3,
                "the refused row is not received again: {again:?}"
            );
            assert!(
                again.iter().all(|row| !row.ends_with("?row=it's")),
                "{again:?}"
            );
            Ok::<_, TransportError>(())
        });
        let rows: [&[Option<&str>]; 4] = [
            &[Some("41"), Some("0x61")],
            &[Some("it's"), Some("0x62")],
            &[Some("43"), Some("0x63")],
            &[None, Some("0x64")],
        ];
        let mut session = accept_one(&far_end, &listener)
            .expect("accepting")
            .with_table(&["id", "payload"], &rows);
        let mut events = Vec::new();
        while let Some(event) = session.next_event().expect("serving") {
            events.push(event);
        }
        receiver.join().expect("thread").expect("receiving");
        assert_eq!(
            events,
            [
                Event::Selected(DEFAULT_QUERY.into()),
                Event::Executed("DELETE FROM inbox WHERE id = N'41'".into()),
                Event::Selected(DEFAULT_QUERY.into()),
            ],
            "the refused, the failed and the unnamed row are left"
        );
    }

    #[test]
    fn a_receive_runs_the_query_and_each_row_is_a_stream() {
        let far_end =
            MssqlTransport::new("127.0.0.1:0", "orders", "xmip").timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            // Two transports, so two sessions: each keeps its own.
            let near = || {
                MssqlTransport::new(address.clone(), "orders", "xmip")
                    .with_query("SELECT id, kind, payload FROM inbox ORDER BY id")
                    .timing_out_after(secs(2))
            };
            let bytes = near().receive().and_then(verdicts);
            (
                bytes,
                near()
                    .holding(Column::Text(Form::Utf16Le))
                    .receive()
                    .and_then(verdicts),
            )
        });
        let rows: [&[Option<&str>]; 2] = [
            &[Some("41"), Some("order"), Some("0x4953412a30302a")],
            &[None, Some("raw"), Some("0xfffe")],
        ];
        let mut session = accept_one(&far_end, &listener)
            .expect("accepting")
            .with_table(&["id", "kind", "payload"], &rows);
        assert_eq!(session.user(), "xmip");
        assert_eq!(session.database(), "orders");
        assert_eq!(session.login().hostname, "xmip");
        let event = session.next_event().expect("query").expect("one");
        assert_eq!(
            event,
            Event::Selected("SELECT id, kind, payload FROM inbox ORDER BY id".into())
        );
        assert!(
            session.next_event().expect("ended").is_none(),
            "a verdict, refused or accepted, says nothing to the database"
        );
        let mut session = accept_one(&far_end, &listener)
            .expect("the text column")
            .with_table(&["id", "payload"], &[&[Some("43"), Some("0x41")]]);
        while session.next_event().expect("event").is_some() {}
        let (arrived, text) = receiver.join().expect("thread");
        let text = text.expect("a text column");
        assert_eq!(
            text[0].bytes,
            codec::utf16::encode("0x41"),
            "text, in its form"
        );
        let arrived = arrived.expect("receiving");
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
        // One server and database, so one login for all three inserts.
        let mut session = accept_one(&far_end, &listener).expect("accepting");
        let first = session.next_insert().expect("first").expect("one");
        assert_eq!(first.bytes, b"it's here");
        assert!(first.origin_uri.ends_with("/orders/inbox/payload"));
        let second = session.next_insert().expect("second").expect("one");
        assert!(
            second.bytes.is_empty(),
            "an empty payload is an empty literal"
        );
        assert!(second.origin_uri.ends_with("/orders/outbox/body"));
        let binary = session.next_insert().expect("third").expect("one");
        assert_eq!(
            binary.bytes,
            [0xff, 0xfe],
            "a binary column, so the binary literal"
        );
        let error = accept_one(&far_end, &listener)
            .err()
            .expect("wrong password");
        assert!(error.message.contains("Login failed"));
        let (bad_target, refused) = sender.join().expect("thread").expect("sending");
        assert!(!bad_target.expect_err("not a column").retryable);
        let refused = refused.expect_err("wrong password");
        assert!(!refused.retryable);
        assert!(refused.message.contains("18456"), "{refused}");
        assert!(far_end.claims().is_some(), "rows are artifacts");
        assert_eq!(far_end.name(), "mssql");
        assert_eq!(far_end.directions(), Directions::BOTH);
    }

    #[test]
    fn a_thousand_inserts_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const SENDS: usize = 1000;
        let far_end = MssqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = MssqlTransport::new(address, "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            for n in 0..SENDS {
                sending.send("inbox/payload", n.to_string().as_bytes())?;
            }
            sending.send("inbox/payload", b"after the close")
        });
        // One pre-login and LOGIN7 for every insert: one session accepted.
        let mut session = accept_one(&far_end, &listener).expect("accepting");
        for n in 0..SENDS {
            let inserted = session.next_insert().expect("insert").expect("one");
            assert_eq!(inserted.bytes, n.to_string().as_bytes());
        }
        drop(session);
        let mut again = accept_one(&far_end, &listener).expect("a new login");
        let last = again.next_insert().expect("insert").expect("one");
        assert_eq!(last.bytes, b"after the close");
        sender.join().expect("thread").expect("sending");
        assert_eq!(near.opened(), 2);
    }

    #[test]
    fn a_thousand_receives_log_in_once_and_a_connection_the_server_closed_is_replaced() {
        const RECEIVES: usize = 1000;
        let far_end = MssqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = MssqlTransport::new(address, "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let receiving = near.clone();
        let receiver = std::thread::spawn(move || {
            for _ in 0..RECEIVES {
                assert_eq!(receiving.receive()?.len(), 1);
            }
            receiving.receive()
        });
        let accept = || {
            accept_one(&far_end, &listener)
                .expect("a login")
                .with_table(&["id", "payload"], &[&[Some("1"), None]])
        };
        // One login for every query: one session accepted.
        let mut session = accept();
        for _ in 0..RECEIVES {
            let event = session.next_event().expect("query");
            assert_matches!(event, Some(Event::Selected(_)), "{event:?}");
        }
        drop(session);
        let mut again = accept();
        assert_matches!(again.next_event(), Ok(Some(Event::Selected(_))));
        assert_eq!(receiver.join().expect("thread").expect("after").len(), 1);
        assert_eq!(near.opened(), 2);
    }

    #[test]
    fn a_text_column_refuses_a_stream_that_is_not_its_encoding() {
        let near =
            MssqlTransport::new("127.0.0.1:1", "orders", "xmip").holding(Column::Text(Form::Utf8));
        let refused = near
            .send("inbox/payload", &[0xff, 0xfe])
            .expect_err("not UTF-8");
        assert!(!refused.retryable);
        assert!(refused.message.contains("utf-8 text"), "{refused}");
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
        let mut session = accept_one(&far_end, &listener)
            .expect("accepting")
            .answering(|sql| {
                sql.contains("[missing]").then(|| Answer::Error {
                    number: 208,
                    message: "Invalid object name 'missing'.".to_string(),
                })
            });
        let event = session.next_event().expect("batch").expect("one");
        assert_matches!(event, Event::Executed(sql) if sql.starts_with("INSERT INTO [missing]"));
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

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = MssqlTransport::loopback();
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
        }
    }

    #[test]
    fn the_login_presents_the_password_the_locations_secret_holds() {
        use transport::secured::Kept;
        let password = Kept::drawn();
        let kept = std::sync::Arc::new(Kept::default());
        kept.set("partner-x.sql", xcore::SecretKind::Password, &password);
        let far_end = MssqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password(password)
            .timing_out_after(secs(2));
        let (listener, address) = far_end.bind().expect("binding");
        let secured = kept.secured("partner-x.sql");
        let sender = std::thread::spawn(move || {
            MssqlTransport::new(address, "orders", "xmip")
                .timing_out_after(secs(2))
                .secured_by(secured)?
                .send("inbox/payload", b"keyed")
        });
        let mut session = accept_one(&far_end, &listener).expect("the login is checked");
        let inserted = session.next_insert().expect("insert").expect("one");
        assert_eq!(inserted.bytes, b"keyed");
        sender.join().expect("thread").expect("sent");
    }
}
