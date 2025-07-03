# Blockchain Commons Depository

<!--Guidelines: https://github.com/BlockchainCommons/secure-template/wiki -->

### _by Wolf McNally_

## Introduction

Blockchain Commons Depository (`depo`) is server-based software that provides
for the secure storage and retrieval of binary objects without regard to their
contents. Typical use cases would be shards of cryptographic seeds or private
keys created using Shamir's Secret Sharing (SSS) or Sharded Secret Key
Reconstruction (SSKR). Various parties can run depositories (depos) to provide a
distributed infrastructure for secure and non-custodial social key recovery.

## Status

This is an early development release. It is not yet ready for production use.

## Database Installation

For macOS development and maintenance I recommend [DBeaver](https://dbeaver.io/)
as a GUI database client.

`depo` was developed using MariaDB, but it should work well with MySQL as well.
The following instructions are for MariaDB.

```bash
$ brew install mariadb
$ brew services start mariadb
$ sudo $(brew --prefix mariadb)/bin/mariadb-admin -u root password NEWPASSWORD
```

For no password (development only!):

```bash
sudo $(brew --prefix mariadb)/bin/mariadb-admin -u root password ''
```

To verify that the brew service is running:

```bash
brew services list | grep mariadb
```

To verify that the server is active and that it is listening on the default port:

```bash
lsof -i :3306
```

To log into the monitor:

```bash
mariadb -u root -p
```

## Depo Installation

After cloning this repository, switch to its directory and run:

```bash
cargo run
```

After it compiles, the server will run. You will see welcome messages, including
the server's public key (`ur:crypto-pubkeys`) which you will need to access its
API. The first time the server runs it will set up the database schema.

In this early development release, it will log into the database as `root` with
no password. Obviously this will be fixed before a production release.

```
[2023-11-16T03:10:21Z INFO  depo::server] Starting Blockchain Commons Depository on 127.0.0.1:5332
[2023-11-16T03:10:21Z INFO  depo::server] Public key: ur:crypto-pubkeys/lftanshfhdcxnnimfnjzlnwkzmrofmluglosetrteyjeonkgchmybbktcmonksbyjocsjkehjllytansgrhdcxlrrkgypmierotkgsgdntpdptntptzegabagmfxdlsgiobnveiypsstjkzoosyahyynimcwze
[2023-11-16T03:10:21Z INFO  warp::server] Server::run; addr=127.0.0.1:5332
[2023-11-16T03:10:21Z INFO  warp::server] listening on http://127.0.0.1:5332
```

To test that it is running, open a browser and navigate to [http://localhost:5332](http://localhost:5332)

You should see the same `ur:crypto-pubkeys` appear in the browser window. This
is the only HTTP GET endpoint in the server. All API access is via POST.

## Learning the API

The API is Trust On First Use (TOFU), so there is no account creation. The first
time a client stores a BLOB, an account is created for it. The client's public
key is used to identify the account.

All requests to the API include the client's public key and must be signed using
the client's private key, and encrypted using the server's public key, which can
be obtained using the HTTP GET endpoint. The server will validate that the
public key in the request matches the key used to sign the request.

All responses from the server are encrypted using the client's public key, and
signed using the server's private key. In addition to decrypting the response
with the client's private key, the client should verify the signature using the
server's public key.

We currently recommend that you examine the [integration
tests](tests/server_test.rs) to learn about the API.

There are nine supported functions:

### Storing, Retrieving, and Deleting BLOBs

* `storeShare` - stores a single BLOB associated with the client's public key,
  returns a Receipt.
* `getShares` - takes a list of `Receipt`s and returns the BLOBs associated with
  the client's public key and those receipts. If the list of receipts is empty,
  it returns all BLOBs associated with the client's public key.
* `deleteShares` - takes a list of `Receipt`s and deletes the BLOBs associated
  with the client's public key and those receipts. If the list of receipts is
  empty, it deletes all BLOBs associated with the client's public key.

### Account Maintenance

* `updateKey` - Updates the client's public key. This is used to change the
  client's public key when necessary.
* `updateRecovery` - Updates or removes the client's recovery method. This is a
  second-factor authentication method that is used to authorize assigning a new
  public key.
* `getRecovery` - Returns the client's recovery method, if any.
* `startRecovery` - Starts the recovery process. This includes a new public key.
  To finish the process, the client must use the second-factor authentication
  method to retrieve a continuation.
* `finishRecovery` - Finishes the recovery process by taking the continuation
  retrieved using the second-factor authentication method. If the continuation
  has not expired, the client's public key is updated to the new public key.
* `deleteAccount` - Deletes the client's account, including all BLOBs and recovery
  method.

## The `depo-api` Crate.

The [`depo-api`](https://crates.io/crates/depo-api) crate provides a Rust API
for the `depo` server. It is intended to be used by clients that want to store
and retrieve BLOBs from a `depo` server. It primarily includes structures and
methods to marshal and unmarshal the API requests and responses.

## Version History

### 0.12.0 - July 3, 2025
- Align to dependencies.
