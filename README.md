# Blockchain Commons Depository

## Introduction

Blockchain Commons Depository (`depo`) is server-based software that provides for the secure storage and retrieval of binary objects without regard to their contents. Typical use cases would be shards of cryptographic seeds or private keys created using Shamir's Secret Sharing (SSS) or Sharded Secret Key Reconstruction (SSKR). Various parties can run depositories (depos) to provide a distributed infrastructure for secure and non-custodial social key recovery.

## Installation

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

To verify that the server is active and that it is listening on port the default port:

```bash
lsof -i :3306
```

To log into the monitor:

```bash
mysql -u root -p
```
