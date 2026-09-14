//! The server's side of one connection: what a test puts at the far end,
//! and what the playground drives.
//!
//! Not a database. One session answers one client's pre-login, checks its
//! login against the one expected — or takes any, where none is — and
//! answers each batch from a closure or from one fixed table: any SELECT
//! gets the table's rows, an INSERT of one column is recorded as a
//! Stream, anything else is done with no rows. Planning, storage and SQL
//! are a database's.

use std::io::BufReader;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use transport::Arrived;
use transport::error::{Result, TransportError, protocol_error};
use transport::socket;
use transport::sql::{self, Answering, Inserted, Rows};

use crate::batch::read_batch;
use crate::column::Column;
use crate::insert::parse_insert;
use crate::login::{Login, Login7, TDS_7_4, read_login7};
use crate::prelogin::{Prelogin, encode_prelogin, read_prelogin};
use crate::token::{
    DONE_COUNT, DONE_ERROR, ENV_DATABASE, ENV_PACKET_SIZE, Message, Token, encode_tokens,
};
use crate::wire::{DEFAULT_PACKET_SIZE, LOGIN7, PRELOGIN, SQL_BATCH, TABULAR_RESULT};
use crate::wire::{read_message, write_message};

/// The number SQL Server answers a refused login with.
pub const LOGIN_FAILED: i32 = 18456;
/// The number it answers a syntax error with.
pub const SYNTAX_ERROR: i32 = 102;

/// What the client did, as [`Session::next_event`] reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The client ran a SELECT; here it is.
    Selected(String),
    /// The client inserted one value; here is the Stream.
    Inserted(Arrived),
    /// The client ran something else; here it is.
    Executed(String),
}

impl Inserted for Event {
    fn inserted(self) -> Option<Arrived> {
        match self {
            Self::Inserted(arrived) => Some(arrived),
            Self::Selected(_) | Self::Executed(_) => None,
        }
    }
}

/// How a batch is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Rows {
        columns: Vec<String>,
        rows: Vec<Vec<Option<String>>>,
    },
    /// Done, this many rows touched.
    Complete(u64),
    Error {
        number: i32,
        message: String,
    },
}

pub struct Session {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    peer: SocketAddr,
    login: Login7,
    columns: Vec<String>,
    rows: Rows<String>,
    answering: Option<Answering<Answer>>,
}

impl Session {
    /// Accept one client on `listener`, answer its pre-login and log it in:
    /// against `expected` where there is one, by taking any login where
    /// there is not.
    ///
    /// # Errors
    /// Where the connection could not be accepted, the client did not open
    /// with a pre-login and a login, or gave the wrong user or password —
    /// which is told to the client as error 18456 before this returns.
    pub fn accept(
        listener: &TcpListener,
        expected: Option<&Login>,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut session = Self {
            reader,
            writer,
            peer,
            login: Login7::new(Login::new("", ""), ""),
            columns: Vec::new(),
            rows: Vec::new(),
            answering: None,
        };
        read_prelogin(&session.read(PRELOGIN)?)?;
        let answer = Prelogin {
            version: [16, 0, 4, 0, 0, 0],
            ..Prelogin::default()
        };
        session.write(TABULAR_RESULT, &encode_prelogin(&answer))?;
        session.login = read_login7(&session.read(LOGIN7)?)?;
        if expected.is_some_and(|expected| *expected != session.login.login) {
            let message = format!("Login failed for user '{}'.", session.user());
            session.write_tokens(&[
                Token::Error(Message::new(LOGIN_FAILED, 14, message.clone())),
                Token::Done {
                    status: DONE_ERROR,
                    rows: 0,
                },
            ])?;
            return Err(TransportError::permanent(message));
        }
        let database = session.database().to_string();
        session.write_tokens(&[
            Token::EnvChange {
                kind: ENV_DATABASE,
                new: database.clone(),
                old: "master".to_string(),
            },
            Token::Info(Message::new(
                5701,
                0,
                format!("Changed database context to '{database}'."),
            )),
            Token::EnvChange {
                kind: ENV_PACKET_SIZE,
                new: DEFAULT_PACKET_SIZE.to_string(),
                old: DEFAULT_PACKET_SIZE.to_string(),
            },
            Token::LoginAck {
                version: TDS_7_4,
                program: "Microsoft SQL Server (xmip)".to_string(),
            },
            Token::Done { status: 0, rows: 0 },
        ])?;
        Ok(session)
    }

    /// The user the client logged in as.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.login.login.user
    }

    /// The database the client asked for.
    #[must_use]
    pub fn database(&self) -> &str {
        &self.login.database
    }

    /// The whole login, host and application included.
    #[must_use]
    pub const fn login(&self) -> &Login7 {
        &self.login
    }

    /// Answer any SELECT with these `columns` and `rows`, every column
    /// `NVARCHAR(MAX)`.
    #[must_use]
    pub fn with_table(mut self, columns: &[&str], rows: &[&[Option<&str>]]) -> Self {
        (self.columns, self.rows) = sql::table(columns, rows);
        self
    }

    /// Answer batches with `answering` first; what it declines falls to
    /// the table.
    #[must_use]
    pub fn answering(
        mut self,
        answering: impl FnMut(&str) -> Option<Answer> + Send + 'static,
    ) -> Self {
        self.answering = Some(Box::new(answering));
        self
    }

    /// The next value the client inserts, or `None` when it closed.
    /// Everything else is answered on the way.
    ///
    /// # Errors
    /// Where the connection broke, or nothing arrived before the timeout.
    pub fn next_insert(&mut self) -> Result<Option<Arrived>> {
        sql::next_insert(|| self.next_event())
    }

    /// The next batch the client ran, answered, or `None` when it closed.
    ///
    /// # Errors
    /// Where the connection broke, nothing arrived before the timeout, or
    /// the client sent what is not a batch.
    pub fn next_event(&mut self) -> Result<Option<Event>> {
        match read_message(&mut self.reader)? {
            None => Ok(None),
            Some((SQL_BATCH, body)) => {
                let sql = read_batch(&body)?;
                let (answer, event) = self.answer(&sql);
                self.write_answer(&answer)?;
                Ok(Some(event))
            }
            Some((other, _)) => Err(protocol_error(format!(
                "packet type {other:#04x} after the login"
            ))),
        }
    }

    /// Answer every batch until the client closes; what it did, in order.
    ///
    /// # Errors
    /// As [`Session::next_event`].
    pub fn serve(&mut self) -> Result<Vec<Event>> {
        let mut events = Vec::new();
        while let Some(event) = self.next_event()? {
            events.push(event);
        }
        Ok(events)
    }

    fn answer(&mut self, sql: &str) -> (Answer, Event) {
        if let Some(answer) = self.answering.as_mut().and_then(|f| f(sql)) {
            return (answer, Event::Executed(sql.to_string()));
        }
        let verb = sql::verb(sql);
        match verb.as_str() {
            "SELECT" => (
                Answer::Rows {
                    columns: self.columns.clone(),
                    rows: self.rows.clone(),
                },
                Event::Selected(sql.to_string()),
            ),
            "INSERT" => match parse_insert(sql) {
                Some((table, column, bytes)) => {
                    let origin =
                        format!("mssql://{}/{}/{table}/{column}", self.peer, self.database());
                    (
                        Answer::Complete(1),
                        Event::Inserted(Arrived::new(origin, bytes)),
                    )
                }
                None => (
                    Answer::Error {
                        number: SYNTAX_ERROR,
                        message: "only INSERT INTO t (c) VALUES (...) is served here".to_string(),
                    },
                    Event::Executed(sql.to_string()),
                ),
            },
            _ => (Answer::Complete(0), Event::Executed(sql.to_string())),
        }
    }

    fn write_answer(&mut self, answer: &Answer) -> Result<()> {
        let tokens = match answer {
            Answer::Rows { columns, rows } => {
                let mut tokens = Vec::with_capacity(rows.len() + 2);
                tokens.push(Token::ColMetadata(
                    columns.iter().map(Column::text).collect(),
                ));
                tokens.extend(rows.iter().cloned().map(Token::Row));
                tokens.push(Token::Done {
                    status: DONE_COUNT,
                    rows: rows.len() as u64,
                });
                tokens
            }
            Answer::Complete(rows) => vec![Token::Done {
                status: DONE_COUNT,
                rows: *rows,
            }],
            Answer::Error { number, message } => vec![
                Token::Error(Message::new(*number, 16, message.clone())),
                Token::Done {
                    status: DONE_ERROR,
                    rows: 0,
                },
            ],
        };
        self.write_tokens(&tokens)
    }

    fn write_tokens(&mut self, tokens: &[Token]) -> Result<()> {
        self.write(TABULAR_RESULT, &encode_tokens(tokens))
    }

    fn write(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        write_message(&mut self.writer, kind, payload, DEFAULT_PACKET_SIZE)
    }

    /// The client's next message, which must be of `kind`.
    fn read(&mut self, kind: u8) -> Result<Vec<u8>> {
        match read_message(&mut self.reader)? {
            Some((got, body)) if got == kind => Ok(body),
            Some((other, _)) => Err(protocol_error(format!(
                "packet type {other:#04x} where {kind:#04x} was due"
            ))),
            None => Err(protocol_error("the client closed before the login")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::wire::packets;
    use std::io::Write as _;

    #[test]
    fn without_an_expected_login_any_login_is_taken_and_a_stray_packet_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let timeout = Some(Duration::from_secs(2));
        let client = std::thread::spawn(move || {
            let login = Login::new("anyone", "whatever");
            let mut client = Client::connect(&address, "orders", &login, timeout).expect("login");
            assert_eq!(client.execute("TRUNCATE TABLE inbox").expect("truncate"), 0);
            let stray = packets(PRELOGIN, &[], DEFAULT_PACKET_SIZE);
            let mut raw = client.writer.try_clone().expect("clone");
            raw.write_all(&stray).expect("write");
            client.close().expect("close");
        });
        let mut session = Session::accept(&listener, None, timeout)
            .expect("accepting")
            .answering(|sql| sql.starts_with("TRUNCATE").then_some(Answer::Complete(0)));
        assert_eq!(session.user(), "anyone");
        assert_eq!(session.login().login.password, "whatever");
        assert_eq!(session.login().app_name, "xmip");
        assert_eq!(
            session.next_event().expect("truncate"),
            Some(Event::Executed("TRUNCATE TABLE inbox".into()))
        );
        let error = session
            .next_event()
            .expect_err("a pre-login after the login");
        assert!(error.message.contains("after the login"), "{error}");
        client.join().expect("thread");
    }
}
