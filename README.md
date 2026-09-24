# xmip-core-transport-mssql

SQL Server transport: one row of a query is one Stream, a send is one INSERT;
TDS 7.4 with SQL Server authentication. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The bracketed identifiers and `N'…'` literals it writes and its far end reads are
`xmip-core-library-codec`'s `sql` module, the one SQL quoting in the estate;
which delimiter is this dialect's own.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
