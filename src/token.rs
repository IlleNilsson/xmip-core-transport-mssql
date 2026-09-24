//! The token stream: what a server answers with, a sequence of tokens
//! each a byte then its body, in one `TABULAR_RESULT` message. Read here
//! as well as written, because the far-end [`crate::Session`] writes
//! exactly these. ENVCHANGE, INFO and ERROR, LOGINACK, COLMETADATA, ROW
//! and NBCROW, DONE in its three forms, RETURNSTATUS and ORDER; a token
//! outside those is refused by its byte, because not every token's
//! length is self-describing and reading past an unknown one is guessing.

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::{Result, protocol_error};

use crate::column::{Column, read_type_info, read_value, write_type_info, write_value};
use crate::wire::{Tds, TdsWrite};

/// The environment changed: a database, a language, a packet size.
pub const ENVCHANGE: u8 = 0xE3;
/// The server failed the batch, or the login.
pub const ERROR: u8 = 0xAA;
/// The server has something to say that is not a failure.
pub const INFO: u8 = 0xAB;
/// The login was accepted.
pub const LOGINACK: u8 = 0xAD;
/// The columns of the rows to come.
pub const COLMETADATA: u8 = 0x81;
/// One row, every column present.
pub const ROW: u8 = 0xD1;
/// One row behind a null bitmap, the null columns absent.
pub const NBCROW: u8 = 0xD2;
/// A statement is done.
pub const DONE: u8 = 0xFD;
/// A procedure is done.
pub const DONEPROC: u8 = 0xFE;
/// A statement inside a procedure is done.
pub const DONEINPROC: u8 = 0xFF;
/// A procedure's return value.
pub const RETURNSTATUS: u8 = 0x79;
/// The columns an `ORDER BY` sorted on.
pub const ORDER: u8 = 0xA9;

/// More results follow this DONE.
pub const DONE_MORE: u16 = 0x0001;
/// The statement failed.
pub const DONE_ERROR: u16 = 0x0002;
/// The row count is meaningful.
pub const DONE_COUNT: u16 = 0x0010;
/// The count COLMETADATA carries when there are no columns.
pub const NO_COLUMNS: u16 = 0xFFFF;
/// ENVCHANGE: the database.
pub const ENV_DATABASE: u8 = 1;
/// ENVCHANGE: the language.
pub const ENV_LANGUAGE: u8 = 2;
/// ENVCHANGE: the packet size.
pub const ENV_PACKET_SIZE: u8 = 4;

/// What INFO and ERROR carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub number: i32,
    pub state: u8,
    pub class: u8,
    pub text: String,
    pub server: String,
    pub procedure: String,
    pub line: u32,
}

impl Message {
    /// `number` of severity `class` saying `text`, from nowhere named.
    #[must_use]
    pub fn new(number: i32, class: u8, text: impl Into<String>) -> Self {
        Self {
            number,
            state: 1,
            class,
            text: text.into(),
            server: String::new(),
            procedure: String::new(),
            line: 1,
        }
    }
}

/// What a server sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    EnvChange {
        kind: u8,
        new: String,
        old: String,
    },
    Info(Message),
    Error(Message),
    LoginAck {
        version: u32,
        program: String,
    },
    ColMetadata(Vec<Column>),
    /// One row, each column as text or null.
    Row(Vec<Option<String>>),
    Done {
        status: u16,
        rows: u64,
    },
    DoneProc {
        status: u16,
        rows: u64,
    },
    DoneInProc {
        status: u16,
        rows: u64,
    },
    ReturnStatus(i32),
    Order(Vec<u16>),
}

/// `tokens` as one payload. A row is written by the metadata before it.
#[must_use]
pub fn encode_tokens(tokens: &[Token]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut columns: Vec<Column> = Vec::new();
    for token in tokens {
        match token {
            Token::EnvChange { kind, new, old } => {
                let mut body = vec![*kind];
                body.b_varchar(new).b_varchar(old);
                push_with_length(&mut out, ENVCHANGE, &body);
            }
            Token::Info(message) => push_with_length(&mut out, INFO, &message_body(message)),
            Token::Error(message) => push_with_length(&mut out, ERROR, &message_body(message)),
            Token::LoginAck { version, program } => {
                let mut body = vec![1u8]; // the SQL_TSQL interface
                body.u32_be(*version)
                    .b_varchar(program)
                    .bytes(&[16, 0, 0, 0]); // the program's version
                push_with_length(&mut out, LOGINACK, &body);
            }
            Token::ColMetadata(declared) => {
                out.push(COLMETADATA);
                if declared.is_empty() {
                    out.u16_le(NO_COLUMNS);
                } else {
                    let count = u16::try_from(declared.len()).unwrap_or(u16::MAX - 1);
                    out.u16_le(count);
                    for column in declared {
                        out.u32_le(0) // user type
                            .u16_le(0x0001); // nullable
                        write_type_info(&mut out, column.kind);
                        out.b_varchar(&column.name);
                    }
                }
                columns.clone_from(declared);
            }
            Token::Row(values) => {
                out.push(ROW);
                for (column, value) in columns.iter().zip(values) {
                    write_value(&mut out, column.kind, value.as_deref());
                }
            }
            Token::Done { status, rows } => push_done(&mut out, DONE, *status, *rows),
            Token::DoneProc { status, rows } => push_done(&mut out, DONEPROC, *status, *rows),
            Token::DoneInProc { status, rows } => push_done(&mut out, DONEINPROC, *status, *rows),
            Token::ReturnStatus(status) => {
                out.push(RETURNSTATUS);
                out.i32_le(*status);
            }
            Token::Order(numbers) => {
                let body: Vec<u8> = numbers.iter().flat_map(|n| n.to_le_bytes()).collect();
                push_with_length(&mut out, ORDER, &body);
            }
        }
    }
    out
}

fn push_with_length(out: &mut Vec<u8>, token: u8, body: &[u8]) {
    out.byte(token)
        .u16_le(u16::try_from(body.len()).unwrap_or(u16::MAX))
        .bytes(body);
}

fn push_done(out: &mut Vec<u8>, token: u8, status: u16, rows: u64) {
    out.byte(token)
        .u16_le(status)
        .u16_le(0) // the current command
        .u64_le(rows);
}

fn message_body(message: &Message) -> Vec<u8> {
    let mut body = Vec::new();
    body.i32_le(message.number)
        .byte(message.state)
        .byte(message.class)
        .us_varchar(&message.text)
        .b_varchar(&message.server)
        .b_varchar(&message.procedure)
        .u32_le(message.line);
    body
}

fn read_message(body: &[u8]) -> Result<Message> {
    let mut cursor = Cursor::new(body);
    Ok(Message {
        number: cursor.i32_le()?,
        state: cursor.byte()?,
        class: cursor.byte()?,
        text: cursor.us_varchar()?,
        server: cursor.b_varchar()?,
        procedure: cursor.b_varchar()?,
        line: cursor.u32_le()?,
    })
}

/// Reads a payload's tokens in order, keeping the columns the last
/// COLMETADATA declared so a ROW can be read by them.
pub struct TokenStream<'a> {
    cursor: Cursor<'a>,
    columns: Vec<Column>,
}

impl<'a> TokenStream<'a> {
    /// A stream at the start of `body`.
    #[must_use]
    pub const fn new(body: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(body),
            columns: Vec::new(),
        }
    }

    /// The columns the last COLMETADATA declared.
    #[must_use]
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// The next token, or `None` at the end of the payload.
    ///
    /// # Errors
    /// A token this crate does not read, a column type it does not read,
    /// or a token that breaks off.
    pub fn next_token(&mut self) -> Result<Option<Token>> {
        if self.cursor.is_empty() {
            return Ok(None);
        }
        let token = self.cursor.byte()?;
        Ok(Some(match token {
            ENVCHANGE => {
                let mut inner = self.body()?;
                let kind = inner.byte()?;
                let (new, old) = if (1..=6).contains(&kind) {
                    (inner.b_varchar()?, inner.b_varchar()?)
                } else {
                    (String::new(), String::new())
                };
                Token::EnvChange { kind, new, old }
            }
            INFO => Token::Info(read_message(self.body()?.remaining())?),
            ERROR => Token::Error(read_message(self.body()?.remaining())?),
            LOGINACK => {
                let mut inner = self.body()?;
                inner.skip(1)?;
                Token::LoginAck {
                    version: inner.u32_be()?,
                    program: inner.b_varchar()?,
                }
            }
            COLMETADATA => {
                let count = self.cursor.u16_le()?;
                let mut columns = Vec::new();
                if count != NO_COLUMNS {
                    for _ in 0..count {
                        self.cursor.skip(6)?; // user type, flags
                        let kind = read_type_info(&mut self.cursor)?;
                        columns.push(Column::new(self.cursor.b_varchar()?, kind));
                    }
                }
                self.columns.clone_from(&columns);
                Token::ColMetadata(columns)
            }
            ROW => {
                let mut values = Vec::with_capacity(self.columns.len());
                for column in &self.columns {
                    values.push(read_value(&mut self.cursor, column.kind)?);
                }
                Token::Row(values)
            }
            NBCROW => {
                let bitmap = self.cursor.take(self.columns.len().div_ceil(8))?;
                let mut values = Vec::with_capacity(self.columns.len());
                for (index, column) in self.columns.iter().enumerate() {
                    if bitmap[index / 8] & (1 << (index % 8)) != 0 {
                        values.push(None);
                    } else {
                        values.push(read_value(&mut self.cursor, column.kind)?);
                    }
                }
                Token::Row(values)
            }
            DONE | DONEPROC | DONEINPROC => {
                let status = self.cursor.u16_le()?;
                self.cursor.skip(2)?;
                let rows = self.cursor.u64_le()?;
                match token {
                    DONE => Token::Done { status, rows },
                    DONEPROC => Token::DoneProc { status, rows },
                    _ => Token::DoneInProc { status, rows },
                }
            }
            RETURNSTATUS => Token::ReturnStatus(self.cursor.i32_le()?),
            ORDER => {
                let mut inner = self.body()?;
                let mut numbers = Vec::new();
                while !inner.is_empty() {
                    numbers.push(inner.u16_le()?);
                }
                Token::Order(numbers)
            }
            other => {
                return Err(protocol_error(format!(
                    "token {other:#04x} is not one this crate reads"
                )));
            }
        }))
    }

    /// A cursor over the body of a token that carries its length.
    fn body(&mut self) -> Result<Cursor<'a>> {
        let length = usize::from(self.cursor.u16_le()?);
        Ok(Cursor::new(self.cursor.take(length)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::column::{ColumnType, MAX};

    #[test]
    fn every_token_round_trips() {
        let tokens = vec![
            Token::EnvChange {
                kind: ENV_DATABASE,
                new: "orders".into(),
                old: "master".into(),
            },
            Token::Info(Message::new(
                5701,
                0,
                "Changed database context to 'orders'.",
            )),
            Token::LoginAck {
                version: 0x7400_0004,
                program: "Microsoft SQL Server".into(),
            },
            Token::ColMetadata(vec![
                Column::new("id", ColumnType::IntN(4)),
                Column::text("payload"),
                Column::new("raw", ColumnType::VarBinary(MAX)),
                Column::new("flag", ColumnType::BitN),
            ]),
            Token::Row(vec![
                Some("41".into()),
                Some("ISA*00*".into()),
                None,
                Some("1".into()),
            ]),
            Token::Row(vec![None, None, Some("0xfffe".into()), None]),
            Token::Order(vec![1]),
            Token::DoneInProc {
                status: DONE_COUNT | DONE_MORE,
                rows: 2,
            },
            Token::ReturnStatus(-1),
            Token::DoneProc {
                status: DONE_MORE,
                rows: 0,
            },
            Token::Error(Message::new(18456, 14, "Login failed for user 'xmip'.")),
            Token::Done {
                status: DONE_ERROR,
                rows: 0,
            },
        ];
        let bytes = encode_tokens(&tokens);
        let mut stream = TokenStream::new(&bytes);
        let mut read = Vec::new();
        while let Some(token) = stream.next_token().expect("read") {
            read.push(token);
        }
        assert_eq!(read, tokens);
        assert_eq!(stream.columns().len(), 4);
    }

    #[test]
    fn a_null_bitmap_row_reads_by_its_columns() {
        let mut bytes = encode_tokens(&[Token::ColMetadata(vec![
            Column::new("id", ColumnType::Int),
            Column::text("payload"),
        ])]);
        bytes.push(NBCROW);
        bytes.push(0b10); // the second column is null
        bytes.extend_from_slice(&7i32.to_le_bytes());
        let mut stream = TokenStream::new(&bytes);
        stream.next_token().expect("metadata");
        assert_eq!(
            stream.next_token().expect("row"),
            Some(Token::Row(vec![Some("7".into()), None]))
        );
        assert!(stream.next_token().expect("end").is_none());
    }

    #[test]
    fn what_is_not_a_token_is_refused() {
        assert!(TokenStream::new(&[0x00]).next_token().is_err(), "unknown");
        assert!(
            TokenStream::new(&[ERROR, 40, 0, 1]).next_token().is_err(),
            "breaks off"
        );
        assert!(
            TokenStream::new(&[DONE, 0, 0]).next_token().is_err(),
            "short"
        );
        let empty = encode_tokens(&[Token::ColMetadata(Vec::new())]);
        assert_eq!(&empty[1..], &[0xFF, 0xFF]);
        assert_eq!(
            TokenStream::new(&empty).next_token().expect("read"),
            Some(Token::ColMetadata(Vec::new()))
        );
    }
}
