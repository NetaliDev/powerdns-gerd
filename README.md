# PowerDNS-Gerd - From Gerðr (/ˈɡerðz̠/; Old Norse for "fenced-in") - A PowerDNS Authorization Proxy

[[_TOC_]]

## Introduction

PowerDNS-Gerd is an authorization proxy for PowerDNS API.

With PowerDNS-Gerd you can provide a multi-user authorization model with granular permissions based on record names and record types.

## API coverage

PowerDNS-Gerd uses [powerdns](https://hackage.haskell.org/package/powerdns) for both talking to the upstream server, as well as providing endpoints. The binding is designed to match every documented API endpoint. PowerDNS-Gerd should therefore re-expose every known endpoint. All endpoints however require correct authentication as minimum, even the api version endpoint.

## Config Format

The config format comes from [config-value](https://hackage.haskell.org/package/config-value). The format is similar to that of YAML, with a few notable differences:

- Comments use OCaml style `-- line comment` and `{- multi-line block comment -}`
- Certain macros can be used

An example config file can be found at [example-config](https://gitlab.com/wobcom/haskell/powerdns-gerd/-/blob/master/powerdns-gerd.conf.example)

PowerDNS-Gerd is self-documenting and will tell you the config schema in a human readable form by invoking

```
$ powerdns-gerd config-help
```

## Permissions

### Zone-wide permissions

You can set

- view
- domains
- delete
- update
- triggerAxfr
- notifySlaves
- getAxfr
- rectifyZone

For documentation how to set each permission, refer to `powerdns-guard config-help`.

Note: The key `domains` implicitly grants updateRecords permissions for the specified zone. If `domains` is set on user-level, this will permit updateRecords on matching records on every zone. 

### Domain permissions

A domain permission consists of a domain label pattern and a record type pattern.

```
{ name: <DOMAIN-LABEL-PATTERN>, types: <RECORD-TYPE-PATTERN> }
```

#### Domain label pattern

The domain label pattern language is described in [dns-patterns](https://hackage.haskell.org/package/dns-patterns-0.2.1/docs/Network-DNS-Pattern.html). In simple terms, any usual domain name representation is a valid Pattern. 

In addition we support the following glob and globstar label patterns
A single asterisk acts as a glob pattern, and matches any single label in place of it. For example `sub.*.example.com` would match `sub.a.example.com` and `sub.b.example.com`. 
A double asterisk acts as a globstar pattern and matches any number of labels. `**.example.com` would match `foo.example.com` and `bar.foo.example.com`. This pattern is currently
only allowed on the leftmost label.

Furthermore, we allow a backslash to act as an escape character for the following three characters:
- `\\` to match a backslash inside a label (byte 0x5)
- `\.` to match a dot inside a label (byte 0x2e)
- `\*` to match an asterisk inside a label (byte 0x2a)
- `\0123` to match an arbitrary byte with that octal representation

#### Record label pattern

A record label pattern is either the atom `any`, which matches any record type, or a list of atoms specifing permissable record types, like `[A, AAAA, TXT, SRV]`.

## Security

PowerDNS-Gerd password verification uses argon2id and is handled by [libsodium](https://libsodium.gitbook.io/doc/). 

The permission model is kept simple in [Permission.hs](https://gitlab.com/wobcom/haskell/powerdns-gerd/-/blob/master/lib/PowerDNS/Gerd/Permission.hs). A set of thorough [tests](https://gitlab.com/wobcom/haskell/powerdns-gerd/-/blob/master/test/Spec.hs) tries to assert that users can only access records they have been granted permission to.

## How is PowerDNS-Gerd different from powerdns-auth-proxy?

powerdns-auth-proxy permissions are linked to account ownership, where a user has complete control over a given zone, and that zone can only be controlled by that same user.

With PowerDNS-Gerd you can assign permissions of particular domains or zones, filterable by record type, to a user. For example, for ACME DNS-01 challenge you usually operate a client like [lego](https://go-acme.github.io/lego/) which would manage `TXT _acme-challenge.example.com`. That client however does not need access to other records.

With PowerDNS-Gerd you can simply specify a permission like:

```
* { name: "_acme-challenge.example.com.", types: [TXT] }
```

which would grant a user access to that record only.

You can also provide glob and globstar patterns like:
```
* { name: "*.zone1.example.com.", types: any }
* { name: "**.example.com.", types: [A, AAAA] }
* { name: "_acme-challenge.*.zone2.example.com.", types: [TXT] }
```
## Build

PowerDNS-Gerd is built with Haskell. To build it yourself, you need [cabal](https://www.haskell.org/cabal/) and [ghc](https://www.haskell.org/ghc/). Both can be easily installed using [ghcup](https://www.haskell.org/ghcup/). Alternative you can install [nix](https://nixos.org/guides/install-nix.html) and use `nix-shell`.

The build required the following native libraries:
- zlib
- libsodium

If you use `nix-shell` these will automatically be provided to you.

To build the software yourself, use:

```
$ cabal build powerdns-gerd
```

The binary artifact can be located using:

```
$ cabal -v0 list-bin powerdns-gerd
```
