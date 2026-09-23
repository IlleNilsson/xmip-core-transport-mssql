//! The client's side of one connection to a server: the pre-login, the
//! login, a batch and its rows, a statement and its count. One batch at a
//! time, every value as text, which is what a Location needs.

use std::io::BufReader;
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use transport::error::{Result, TransportError, protocol_error};
use transport::socket;

use crate::batch::encode_batch;
use crate::login::{Login, Login7, encode_login7};
use crate::prelogin::{ENCRYPT_NOT_SUP, ENCRYPT_OFF, Prelogin, encode_prelogin, read_prelogin};
use crate::token::{DONE_COUNT, ENV_PACKET_SIZE, Message, Token, TokenStream};
use crate::wire::{
    DEFAULT_PACKET_SIZE, LOGIN7, MAX_PACKET_SIZE, MIN_PACKET_SIZE, PRELOGIN, SQL_BATCH,
    TABULAR_RESULT, read_message, write_message,
};

/// What a batch came back with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryResult {
    pub columns: Vec<String>,
    /// Each row, each column as text or null.
    pub rows: Vec<Vec<Option<String>>>,
    /// What the last DONE that counted said.
    pub rows_affected: u64,
}

pub struct Client {
    reader: BufReader<TcpStream>,
    pub(crate) writer: TcpStream,
    packet_size: u16,
    program: String,
}

impl Client {
    /// Connect to `server`, log in as `login` and use `database`.
    ///
    /// # Errors
    /// Where the server could not be reached, requires encryption, or
    /// refused the login.
    pub fn connect(
        server: &str,
        database: &str,
        login: &Login,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = socket::connect_tcp(server, timeout)?;
        let (reader, writer) = socket::split(stream)?;
        let mut client = Self {
            reader,
            writer,
            packet_size: DEFAULT_PACKET_SIZE,
            program: String::new(),
        };
        client.write(PRELOGIN, &encode_prelogin(&Prelogin::default()))?;
        let answer = read_prelogin(&client.read()?)?;
        if answer.encryption != ENCRYPT_NOT_SUP && answer.encryption != ENCRYPT_OFF {
            return Err(TransportError::permanent(
                "the server requires encryption, and TLS is `xmip-core-tls`'s (ADR-0033)",
            ));
        }
        let login = Login7::new(login.clone(), database);
        client.write(LOGIN7, &encode_login7(&login))?;
        let body = client.read()?;
        let mut tokens = TokenStream::new(&body);
        let mut acknowledged = false;
        while let Some(token) = tokens.next_token()? {
            match token {
                Token::LoginAck { program, .. } => {
                    client.program = program;
                    acknowledged = true;
                }
                Token::EnvChange {
                    kind: ENV_PACKET_SIZE,
                    new,
                    ..
                } => {
                    if let Ok(size) = new.parse::<u16>() {
                        client.packet_size = size.clamp(MIN_PACKET_SIZE, MAX_PACKET_SIZE);
                    }
                }
                Token::Error(message) => return Err(sql_error(&message)),
                _ => {}
            }
        }
        if !acknowledged {
            return Err(protocol_error("the server did not acknowledge the login"));
        }
        Ok(client)
    }

    /// What the server called itself at login.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The packet size the server settled on.
    #[must_use]
    pub const fn packet_size(&self) -> u16 {
        self.packet_size
    }

    /// Run `sql` and take its rows.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn query(&mut self, sql: &str) -> Result<QueryResult> {
        self.write(SQL_BATCH, &encode_batch(sql))?;
        let body = self.read()?;
        let mut tokens = TokenStream::new(&body);
        let mut result = QueryResult::default();
        let mut failed = None;
        while let Some(token) = tokens.next_token()? {
            match token {
                Token::ColMetadata(columns) => {
                    result.columns = columns.into_iter().map(|c| c.name).collect();
                }
                Token::Row(values) => result.rows.push(values),
                Token::Error(message) => failed = Some(sql_error(&message)),
                Token::Done { status, rows }
                | Token::DoneProc { status, rows }
                | Token::DoneInProc { status, rows }
                    if status & DONE_COUNT != 0 =>
                {
                    result.rows_affected = rows;
                }
                _ => {}
            }
        }
        failed.map_or(Ok(result), Err)
    }

    /// Run `sql` for its effect; the rows it touched.
    ///
    /// # Errors
    /// Where the server went away or answered with an error.
    pub fn execute(&mut self, sql: &str) -> Result<u64> {
        self.query(sql).map(|result| result.rows_affected)
    }

    /// Hang up. The protocol has no goodbye; closing the socket is it.
    ///
    /// # Errors
    /// Where the socket refused to close.
    pub fn close(self) -> Result<()> {
        match self.writer.shutdown(Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(transport::error::classify("closing the connection", &error)),
        }
    }

    fn write(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        write_message(&mut self.writer, kind, payload, self.packet_size)
    }

    /// The server's next answer, which is always a token stream.
    fn read(&mut self) -> Result<Vec<u8>> {
        match read_message(&mut self.reader)? {
            Some((TABULAR_RESULT, body)) => Ok(body),
            Some((other, _)) => Err(protocol_error(format!(
                "packet type {other:#04x} is not a server's answer"
            ))),
            None => Err(protocol_error("the server closed mid-conversation")),
        }
    }
}

/// An error the server answered, retryable where its number says the
/// trouble is a deadlock, a lock, memory, the connection or a service
/// that is busy or moving — what a later attempt might not meet.
#[must_use]
pub fn sql_error(message: &Message) -> TransportError {
    let text = format!("the server answered {}: {}", message.number, message.text);
    match message.number {
        -2 | 233 | 1204 | 1205 | 1222 | 8645 | 8651 | 10053 | 10054 | 10060 | 40197 | 40501
        | 40613 | 49918 | 49919 | 49920 => TransportError::retryable(text),
        _ => TransportError::permanent(text),
    }
}

/// `text` as a Unicode string literal: `N`, quoted, every quote doubled.
/// `N` because a plain literal is the server's single-byte collation and
/// a Stream is UTF-8.
#[must_use]
pub fn quote_literal(text: &str) -> String {
    format!("N'{}'", text.replace('\'', "''"))
}

/// `name` as an identifier: bracketed, every closing bracket doubled.
#[must_use]
pub fn quote_identifier(name: &str) -> String {
    format!("[{}]", name.replace(']', "]]"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Answer, Event, Session};
    use std::net::TcpListener;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn quoting_doubles_the_delimiter_and_nothing_else() {
        assert_eq!(quote_literal("it's"), "N'it''s'");
        assert_eq!(quote_literal("back\\slash"), "N'back\\slash'");
        assert_eq!(quote_literal(""), "N''");
        assert_eq!(quote_identifier("in]box"), "[in]]box]");
        assert_eq!(quote_identifier("In box"), "[In box]");
    }

    #[test]
    fn an_error_is_judged_by_its_number() {
        assert!(sql_error(&Message::new(1205, 13, "deadlock victim")).retryable);
        assert!(sql_error(&Message::new(-2, 11, "timeout")).retryable);
        assert!(sql_error(&Message::new(40613, 20, "database not available")).retryable);
        assert!(!sql_error(&Message::new(18456, 14, "Login failed")).retryable);
        assert!(!sql_error(&Message::new(208, 16, "Invalid object name")).retryable);
    }

    #[test]
    fn a_client_logs_in_queries_executes_and_is_told_of_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let far_end = std::thread::spawn(move || {
            let expected = Login::new("xmip", "secret");
            let mut session = Session::accept(&listener, Some(&expected), Some(secs(2)))
                .expect("accepting")
                .with_table(
                    &["id", "payload"],
                    &[&[Some("1"), None], &[None, Some("x")]],
                )
                .answering(|sql| {
                    sql.contains("boom").then(|| Answer::Error {
                        number: 208,
                        message: "Invalid object name 'boom'.".to_string(),
                    })
                });
            let events = session.serve().expect("serving");
            (
                session.user().to_string(),
                session.database().to_string(),
                events,
            )
        });
        let login = Login::new("xmip", "secret");
        let mut client = Client::connect(&address, "orders", &login, Some(secs(2))).expect("login");
        assert!(client.program().contains("SQL Server"));
        assert_eq!(client.packet_size(), DEFAULT_PACKET_SIZE);
        let result = client
            .query("SELECT id, payload FROM inbox")
            .expect("query");
        assert_eq!(result.columns, ["id", "payload"]);
        assert_eq!(
            result.rows,
            [[Some("1".to_string()), None], [None, Some("x".to_string())]]
        );
        assert_eq!(result.rows_affected, 2);
        assert_eq!(client.execute("DELETE FROM inbox").expect("execute"), 0);
        let error = client.query("SELECT * FROM boom").expect_err("errored");
        assert!(error.message.contains("208"), "{error}");
        assert!(!error.retryable);
        client.close().expect("close");
        let (user, database, events) = far_end.join().expect("thread");
        assert_eq!(user, "xmip");
        assert_eq!(database, "orders");
        assert_eq!(events.len(), 3);
        assert_eq!(events[1], Event::Executed("DELETE FROM inbox".into()));
    }

    #[test]
    fn a_server_that_requires_encryption_or_speaks_nonsense_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        std::thread::spawn(move || {
            let demand = encode_prelogin(&Prelogin {
                encryption: crate::prelogin::ENCRYPT_REQ,
                ..Prelogin::default()
            });
            let no_ack = crate::token::encode_tokens(&[Token::Done { status: 0, rows: 0 }]);
            for answer in [
                crate::wire::packets(TABULAR_RESULT, &demand, DEFAULT_PACKET_SIZE),
                crate::wire::packets(SQL_BATCH, &demand, DEFAULT_PACKET_SIZE),
                b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec(),
                crate::wire::packets(TABULAR_RESULT, &no_ack, DEFAULT_PACKET_SIZE),
            ] {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut sink = [0u8; 1024];
                let _ = std::io::Read::read(&mut stream, &mut sink);
                if answer == crate::wire::packets(TABULAR_RESULT, &no_ack, DEFAULT_PACKET_SIZE) {
                    let agreed = encode_prelogin(&Prelogin::default());
                    let packet = crate::wire::packets(TABULAR_RESULT, &agreed, DEFAULT_PACKET_SIZE);
                    std::io::Write::write_all(&mut stream, &packet).expect("write");
                    let _ = std::io::Read::read(&mut stream, &mut sink);
                }
                std::io::Write::write_all(&mut stream, &answer).expect("write");
                let _ = std::io::Read::read(&mut stream, &mut sink);
            }
        });
        let login = Login::new("xmip", "");
        let connect = || Client::connect(&address, "orders", &login, Some(secs(2)));
        let error = connect().err().expect("encryption");
        assert!(!error.retryable);
        assert!(error.message.contains("ADR-0033"), "{error}");
        assert!(
            connect()
                .err()
                .expect("wrong type")
                .message
                .contains("0x01")
        );
        assert!(!connect().err().expect("not the protocol").retryable);
        assert!(
            connect()
                .err()
                .expect("no ack")
                .message
                .contains("acknowledge")
        );
    }
}
