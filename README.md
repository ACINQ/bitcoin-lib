# Simple Scala Bitcoin Library

Simple bitcoin library written in Scala.

## Overview

This is a simple scala library which implements some (most ?) of the bitcoin protocol:

* base58 encoding/decoding
* block headers, block and tx parsing
* tx signature and verification
* script parsing and execution
* pay to public key tx
* pay to script tx / multisig tx
* BIP 32 (deterministic wallets)
* BIP 70

## Limitations and compatibility issues

This is a very early beta release and should not be used in production. If you're looking for a mature bitcoin library for the JVM you should
have a look at bitcoinj instead.

Not all script instructions have been implemented, but as is the library should be able to parse and validate the entire blockchain.

## Building

Just clone the repo and build with maven (version 3 and above). Artifacts will soon be published to maven central.

## Usage

Please have a look at unit tests, more samples will be added soon.

