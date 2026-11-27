//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`. Its wire
//! hands it to `transport::sql`'s `Configured`. What every SQL Location
//! declares stays `transport::sql`'s.

use transport::sql::accept::ACCEPT;
use transport::sql::{COLUMN, DATABASE, ENCODING, QUERY, TIMEOUT, USER};
use xcore::settings::Settings;

/// Every setting a SQL Server Location takes beyond its address, the
/// server, `host:1433`, both sides log in to.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[DATABASE, USER, QUERY, ACCEPT, COLUMN, ENCODING, TIMEOUT],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["mssql", "sqlserver"];
