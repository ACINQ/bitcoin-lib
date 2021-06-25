# Simple Scala Bitcoin Library

Simple bitcoin library written in Scala.

[![Build Status](https://github.com/ACINQ/bitcoin-lib/workflows/Build%20&%20Test/badge.svg)](https://github.com/ACINQ/bitcoin-lib/actions?query=workflow%3A%22Build+%26+Test%22)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Overview

This is a simple scala library which implements most of the bitcoin protocol:

* base58 encoding/decoding
* block headers, block and tx parsing
* tx creation, signature and verification
* script parsing and execution (including OP_CLTV and OP_CSV)
* pay to public key tx
* pay to script tx / multisig tx
* BIP 32 (deterministic wallets)
* BIP 39 (mnemonic code for generating deterministic keys)
* BIP 173 (Base32 address format for native v0-16 witness outputs)
* BIP 174 (Partially Signed Bitcoin Transaction Format)
* BIP 350 (Bech32m format)

## Objectives

Our goal is not to re-implement a full Bitcoin node but to build a library that can be used to build applications that rely on bitcoind to interface with the Bitcoin network (to retrieve and index transactions and blocks, for example...). We use it very often to build quick prototypes and test new ideas. Besides, some parts of the protocole are fairly simple and "safe" to re-implement (BIP32/BIP39 for example), especially for indexing/analysis purposes. And, of course, we use it for our own work on Lightning (see https://github.com/ACINQ/eclair).

## Status

* [X] Message parsing (blocks, transactions, inv, ...)
* [X] Building transactions (P2PK, P2PKH, P2SH, P2WPK, P2WSH)
* [X] Signing transactions
* [X] Verifying signatures
* [X] Passing core reference tests (scripts & transactions)
* [X] Passing core reference segwit tests
* [X] Passing core reference psbt tests

## Configuring maven/sbt

* releases and milestones are pushed to maven central
* snapshots are pushed to the sonatype snapshot repository

```xml
 <repositories>
    <repository>
        <id>sonatype snapshots</id>
        <url>https://oss.sonatype.org/content/repositories/snapshots/</url>
    </repository>
</repositories>

<dependencies>
  <dependency>
    <groupId>fr.acinq</groupId>
    <artifactId>bitcoin-lib_2.11</artifactId>
    <version>0.16</version>
  </dependency>
</dependencies>
```

The latest snapshot (development) version is 0.17-SNAPSHOT, the latest released version is 0.16.

## Segwit support

Bitcoin-lib, starting with version 0.9.7, fully supports segwit (see below for more information) and is on par with the segwit code in Bitcoin Core 0.13.1.

## libsecp256k1 support

Bitcoin-lib embeds JNI bindings for libsecp256k1, which is must faster than BouncyCastle. It will extract and load native bindings for your operating system in a temporary directory. If this process fails it will fallback to BouncyCastle.

JNI libraries are included for:

* Linux 64 bits
* Windows 64 bits
* Osx 64 bits

You can use your own library native library by specifying its path with `-Dfr.acinq.secp256k1.lib.path` and optionally its name with `-Dfr.acinq.secp256k1.lib.name` (if unspecified bitcoin-lib will use the standard name for your OS i.e. libsecp256k1.so on Linux, secp256k1.dll on Windows, ...).

You can also specify the temporary directory where the library will be extracted with `-Djava.io.tmpdir` or `-Dfr.acinq.secp256k1.tmpdir` (if you want to use a different directory from `-Djava.io.tmpdir`).

## Usage

Please have a look at unit tests, more samples will be added soon.

### Basic type: public keys, private keys, addresses

We defined only a limited set of specific types (private keys, public keys). There is a simple BinaryData type
that can be used to convert to/from Array[Byte], Seq[Byte], and hexadecimal Strings.

As much as possible, the library uses and produces raw binary data, without fancy wrapper types and encoding. This should
make importing/exporting data from/to other libraries easy. It also makes it easy to use binary data used in examples, books,
or produced by debugging tools.

The following REPL session shows how to create and use keys and addresses:

```shell
mvn scala:console
scala> import fr.acinq.bitcoin._
import fr.acinq.bitcoin._

scala> import fr.acinq.bitcoin.Crypto._
import fr.acinq.bitcoin.Crypto._

scala> import scodec.bits._
import scodec.bits._

scala> val priv = PrivateKey(hex"1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd")
priv: fr.acinq.bitcoin.Crypto.PrivateKey = PrivateKey(1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd)

scala> val pub = priv.publicKey
pub: fr.acinq.bitcoin.Crypto.PublicKey = 03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a    ^

scala> Base58Check.encode(Base58.Prefix.PubkeyAddress, pub.hash160)
res0: String = 1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy

scala> priv.toBase58(Base58.Prefix.SecretKey)
res2: String = KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ
```

### Building and verifying transactions

The Transaction class can be used to create, serialize, deserialize, sign and validate bitcoin transactions.

#### P2PKH transactions

A P2PKH transactions sends bitcoins to a public key hash, using a standard P2PKH script:

``` scala
val pkh = pubKey.hash160
val pubKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(pkh) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil
```

To spend it, just provide a signature and the public key:

```scala
val sigScript = OP_PUSHDATA(sig) :: OP_PUSHDATA(pubKey.toBin) :: Nil
```

This sample demonstrates how to serialize, create and verify simple P2PKH transactions.

```scala
    // simple pay to PK tx

    // we have a tx that was sent to a public key that we own
    val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
    val (Base58.Prefix.PubkeyAddressTestnet, pubkeyHash) = Base58Check.decode(to)
    val amount = 10000 sat

    val privateKey = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
    val publicKey = privateKey.publicKey

    val previousTx = Transaction.read("0100000001b021a77dcaad3a2da6f1611d2403e1298a902af8567c25d6e65073f6b52ef12d000000006a473044022056156e9f0ad7506621bc1eb963f5133d06d7259e27b13fcb2803f39c7787a81c022056325330585e4be39bcf63af8090a2deff265bc29a3fb9b4bf7a31426d9798150121022dfb538041f111bb16402aa83bd6a3771fa8aa0e5e9b0b549674857fafaf4fe0ffffffff0210270000000000001976a91415c23e7f4f919e9ff554ec585cb2a67df952397488ac3c9d1000000000001976a9148982824e057ccc8d4591982df71aa9220236a63888ac00000000")

    // create a transaction where the sig script is the pubkey script of the tx we want to redeem
    // the pubkey script is just a wrapper around the pub key hash
    // what it means is that we will sign a block of data that contains txid + from + to + amount

    // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
    val tx1 = Transaction(
      version = 1L,
      txIn = List(
        TxIn(OutPoint(previousTx, 0), signatureScript = Nil, sequence = 0xFFFFFFFFL)
      ),
      txOut = List(
        TxOut(amount = amount, publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(pubkeyHash) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)
      ),
      lockTime = 0L
    )

    // step #2: sign the tx
    val sig = Transaction.signInput(tx1, 0, previousTx.txOut(0).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, privateKey)
    val tx2 = tx1.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(publicKey) :: Nil)

    // redeem the tx
    Transaction.correctlySpends(tx2, Seq(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
```

#### P2SH transactions

A P2SH transactions sends bitcoins to a script hash:

```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub1, pub2, pub3 ))
val multisigAddress = Crypto.hash160(redeemScript)
val publicKeyScript = OP_HASH160 :: OP_PUSHDATA(multisigAddress) :: OP_EQUAL :: Nil
```

To spend it, you must provide data that will match the public key script, and the actual public key script. In our case,
we need 2 valid signatures:

```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub1, pub2, pub3 ))
val sigScript = OP_0 :: OP_PUSHDATA(sig1) :: OP_PUSHDATA(sig2) :: OP_PUSHDATA(redeemScript) :: Nil
```

This sample demonstrates how to serialize, create and verify a multisig P2SH transaction

```scala
    val priv1 = PrivateKey.fromBase58("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT", Base58.Prefix.SecretKeySegnet)._1
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressSegnet, Crypto.hash160(pub1.value))

    assert(address1 == "D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap")

    val priv2 = PrivateKey.fromBase58("QUpr3G5ia7K7txSq5k7QpgTfNy33iTQWb1nAUgb77xFesn89xsoJ", Base58.Prefix.SecretKeySegnet)._1
    val pub2 = priv2.publicKey

    val priv3 = PrivateKey.fromBase58("QX3AN7b3WCAFaiCvAS2UD7HJZBsFU6r5shjfogJu55411hAF3BVx", Base58.Prefix.SecretKeySegnet)._1
    val pub3 = priv3.publicKey

    // this is a standard tx that sends 0.5 BTC to D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap
    val tx1 = Transaction.read("010000000240b4f27534e9d5529e67e52619c7addc88eff64c8e7afc9b41afe9a01c6e2aea010000006b48304502210091aed7fe956c4b2471778bfef5a323a96fee21ec6d73a9b7f363beaad135c5f302207f63b0ffc08fd905cdb87b109416c2d6d8ec56ca25dd52529c931aa1154277f30121037cb5789f1ca6c640b6d423ef71390e0b002da81db8fad4466bf6c2fdfb79a24cfeffffff6e21b8c625d9955e48de0a6bbcd57b03624620a93536ddacabc19d024c330f04010000006a47304402203fb779df3ae2bf8404e6d89f83af3adee0d0a0c4ec5a01a1e88b3aa4313df6490220608177ca82cf4f7da9820a8e8bf4266ccece9eb004e73926e414296d0635d7c1012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019feffffff0280f0fa02000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ace06d9800000000001976a91457572594090c298721e8dddcec3ac1ec593c6dcc88ac205a0000", pversion)

    // now let's create a simple tx that spends tx1 and send 0.5 BTC to a P2WSH output
    val tx2 = {
      // our script is a 2-of-2 multisig script
      val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.49 btc, Script.pay2wsh(redeemScript)) :: Nil,
        lockTime = 0
      )
      val sig = Transaction.signInput(tmp, 0, tx1.txOut(0).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, priv1)
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
      //Transaction.sign(tmp, Seq(SignData(tx1.txOut(0).publicKeyScript, priv1)))
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == ByteVector32(hex"9d896b6d2b8fc9665da72f5b1942f924a37c5c714f31f40ee2a6c945f74dd355"))
    // this tx was published on segnet as 9d896b6d2b8fc9665da72f5b1942f924a37c5c714f31f40ee2a6c945f74dd355

    // and now we create a segwit tx that spends the P2WSH output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.48 btc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
      val sig2 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv2)
      val sig3 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv3)
      val witness = ScriptWitness(Seq(ByteVector.empty, sig2, sig3, pubKeyScript))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == ByteVector32(hex"943e07f0c66a9766d0cec81d65a03db4157bc0bfac4d36e400521b947be55aeb"))
    // this tx was published on segnet as 943e07f0c66a9766d0cec81d65a03db4157bc0bfac4d36e400521b947be55aeb
```

#### P2WPK transactions

This is the simplest segwit transaction, equivalent to standard P2PKH transactions but more compact:

```scala
val pkh = pubKey.hash160
val pubKeyScript = OP_0 :: OP_PUSHDATA(pkh) :: Nil
```

To spend them, you provide a witness that is just a push of a signature and the actual public key:

```scala
val witness = ScriptWitness(sig :: pubKey :: Nil))
```

This sample demonstrates how to serialize, create and verify a P2WPK transaction

```scala
    val priv1 = PrivateKey.fromBase58("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT", Base58.Prefix.SecretKeySegnet)._1
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressSegnet, Crypto.hash160(pub1.value))

    assert(address1 == "D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap")

    // this is a standard tx that sends 0.4 BTC to D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap
    val tx1 = Transaction.read("010000000001014d5a1833ddd78613408d66b0189e3171aa3b5d1a5b2df4392749d39291ea73cd0000000000feffffff02005a6202000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ac048b9800000000001976a914eb7c97a96fa9205b8a772d0c1d170e90a8a3098388ac02483045022100e2ccc1ab7e7e0c6bcbbdd4d9935448011b415fc1ec774416aa2760c3ae08431d022064ad6fd7c952df2b3f06a9cf94ddc9856c734c46ad43d0ab45d5ddf3b7deeef0012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019ae590000", pversion)

    // now let's create a simple tx that spends tx1 and send 0.39 BTC to P2WPK output
    val tx2 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty, witness = ScriptWitness.empty) :: Nil,
        txOut = TxOut(0.39 btc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      val sig = Transaction.signInput(tmp, 0, tx1.txOut(0).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, priv1)
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == ByteVector32(hex"3acf933cd1dbffbb81bb5c6fab816fdebf85875a3b77754a28f00d717f450e1e"))
    // this tx was published on segnet as 3acf933cd1dbffbb81bb5c6fab816fdebf85875a3b77754a28f00d717f450e1e

    // and now we create a segwit tx that spends the P2WPK output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty, witness = ScriptWitness.empty) :: Nil,
        txOut = TxOut(0.38 btc, Script.pay2wpkh(pub1)) :: Nil, // we reuse the same output script but if could be anything else
        lockTime = 0
      )
      // mind this: the pubkey script used for signing is not the prevout pubscript (which is just a push
      // of the pubkey hash), but the actual script that is evaluated by the script engine, in this case a PAY2PKH script
      val pubKeyScript = Script.pay2pkh(pub1)
      val sig = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)
      val witness = ScriptWitness(Seq(sig, pub1.value))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == ByteVector32(hex"a474219df20b95210b8dac45bb5ed49f0979f8d9b6c17420f3e50f6abc071af8"))
    // this tx was published on segnet as a474219df20b95210b8dac45bb5ed49f0979f8d9b6c17420f3e50f6abc071af8
```

#### P2WSH transactions

P2WSH transactions are the segwit version of P2SH transactions:

```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
val pubKeyScript = OP_0 :: OP_PUSHDATA(Crypto.sha256(redeemScript)) :: Nil) :: Nil,
```

To spend them, you provide data that wil match the publick key script, and the actual public key script:

```scala
val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
val witness = ScriptWitness(Seq(ByteVector.empty, sig2, sig3, redeemScript))
```

This sample demonstrates how to serialize, create and verify a P2WPSH transaction

```scala
    val priv1 = PrivateKey.fromBase58("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT", Base58.Prefix.SecretKeySegnet)._1
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressSegnet, Crypto.hash160(pub1.value))

    assert(address1 == "D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap")

    val priv2 = PrivateKey.fromBase58("QUpr3G5ia7K7txSq5k7QpgTfNy33iTQWb1nAUgb77xFesn89xsoJ", Base58.Prefix.SecretKeySegnet)._1
    val pub2 = priv2.publicKey

    val priv3 = PrivateKey.fromBase58("QX3AN7b3WCAFaiCvAS2UD7HJZBsFU6r5shjfogJu55411hAF3BVx", Base58.Prefix.SecretKeySegnet)._1
    val pub3 = priv3.publicKey

    // this is a standard tx that sends 0.5 BTC to D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap
    val tx1 = Transaction.read("010000000240b4f27534e9d5529e67e52619c7addc88eff64c8e7afc9b41afe9a01c6e2aea010000006b48304502210091aed7fe956c4b2471778bfef5a323a96fee21ec6d73a9b7f363beaad135c5f302207f63b0ffc08fd905cdb87b109416c2d6d8ec56ca25dd52529c931aa1154277f30121037cb5789f1ca6c640b6d423ef71390e0b002da81db8fad4466bf6c2fdfb79a24cfeffffff6e21b8c625d9955e48de0a6bbcd57b03624620a93536ddacabc19d024c330f04010000006a47304402203fb779df3ae2bf8404e6d89f83af3adee0d0a0c4ec5a01a1e88b3aa4313df6490220608177ca82cf4f7da9820a8e8bf4266ccece9eb004e73926e414296d0635d7c1012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019feffffff0280f0fa02000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ace06d9800000000001976a91457572594090c298721e8dddcec3ac1ec593c6dcc88ac205a0000", pversion)

    // now let's create a simple tx that spends tx1 and send 0.5 BTC to a P2WSH output
    val tx2 = {
      // our script is a 2-of-2 multisig script
      val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.49 btc, Script.pay2wsh(redeemScript)) :: Nil,
        lockTime = 0
      )
      val sig = Transaction.signInput(tmp, 0, tx1.txOut(0).publicKeyScript, SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, priv1)
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
      //Transaction.sign(tmp, Seq(SignData(tx1.txOut(0).publicKeyScript, priv1)))
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == ByteVector32(hex"9d896b6d2b8fc9665da72f5b1942f924a37c5c714f31f40ee2a6c945f74dd355"))
    // this tx was published on segnet as 9d896b6d2b8fc9665da72f5b1942f924a37c5c714f31f40ee2a6c945f74dd355

    // and now we create a segwit tx that spends the P2WSH output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.48 btc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
      val sig2 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv2)
      val sig3 = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv3)
      val witness = ScriptWitness(Seq(ByteVector.empty, sig2, sig3, pubKeyScript))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == ByteVector32(hex"943e07f0c66a9766d0cec81d65a03db4157bc0bfac4d36e400521b947be55aeb"))
    // this tx was published on segnet as 943e07f0c66a9766d0cec81d65a03db4157bc0bfac4d36e400521b947be55aeb
```

#### Segwit transactions embedded in standard P2SH transactions

```scala
    val priv1 = PrivateKey.fromBase58("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT", Base58.Prefix.SecretKeySegnet)._1
    val pub1 = priv1.publicKey

    // p2wpkh script
    val script = Script.write(Script.pay2wpkh(pub1))

    // which we embeed into a standard p2sh script
    val p2shaddress = Base58Check.encode(Base58.Prefix.ScriptAddressSegnet, Crypto.hash160(script))
    assert(p2shaddress === "MDbNMghDbaaizHz8pSgMqu9qJXvKwouqkM")

    // this tx send 0.5 btc to our p2shaddress
    val tx = Transaction.read("010000000175dd435bf25e5d77567272f7d6eefcf37b7156b78bb233490140d6fa7545cfca010000006a47304402206e601a482b301141cb3a1712c18729fa1f1731fce5c4205ac9d344af38bb24bf022003fe70edcbd1a5b3957b3c939e583739eadb8de8d3d2cc2ad2903b19c991cb80012102ba2558223d7cd5df2d8decc4506a62ccaa96159f685360335c280952b25e7adefeffffff02692184df000000001976a9148b3ee15d631122010d31e1774aa318ca9ca8b67088ac80f0fa020000000017a9143e73638f202bb880a28e8df1946adc3058227d11878c730000", pversion)

    // let's spend it:

    val tx1 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx.hash, 1), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.49 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1.value)) :: Nil) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.pay2pkh(pub1)
      val sig = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx.txOut(1).amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)
      val witness = ScriptWitness(Seq(sig, pub1.value))
      tmp.updateSigScript(0, OP_PUSHDATA(script) :: Nil).updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx1, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx1.txid === ByteVector32(hex"98f5668176b0c1b14653f96f71987fd325c3d46b9efb677ab0606ea5555791d5"))
    // this tx was published on segnet as 98f5668176b0c1b14653f96f71987fd325c3d46b9efb677ab0606ea5555791d5
```

#### Partially Signed Transactions

Bitcoin-lib provides low-level support for reading, writing and manipulating PSBTs.
Bitcoin-lib is *not* compatible with Bitcoin Core versions before 0.20.1, because we include the `nonWitnessUtxo` for segwit inputs: see [BIP 174 - note 8](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#cite_note-8) for details.

```scala
    val aliceKeyNonWitness = PrivateKey(hex"2c6ba77e9184c5b6c6215f84ef0e00558884dec7d23a027f0573d11bf77aff46")
    val bobKeyNonWitness = PrivateKey(hex"a4ed1609f90afbb52e37b44a0c548aed5c878bc0f029fc9a1131c4402e9234e0")
    val aliceKeyWitness = PrivateKey(hex"68cfa8072f964148cb0dcedae42bbab417872739afef513314b29619ff3de9c4")
    val bobKeyWitness = PrivateKey(hex"11f4a287b28488c18351c5fa1136a5b30c2de63c30827b9460ff62bc246b366d")

    // This PSBT has been initialized with an unsigned transaction containing two multi-sig inputs:
    val Success(psbtNotFunded) = Psbt.read(hex"70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000".toArray)
    assert(psbt.global.version === 0)
    assert(psbt.global.tx.txIn.length === 2)
    assert(psbt.global.tx.txOut.length === 2)

    // Provide information about the first input:
    val tx1 = Transaction.read(hex"0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000".toArray)
    val Success(oneInputFilled) = psbtNotFunded.update(
      tx1,
      outputIndex = 0,
      Some(Script.createMultiSigMofN(2, Seq(aliceKeyNonWitness.publicKey, bobKeyNonWitness.publicKey)))
    )

    // Provide information about the second input:
    val tx2 = Transaction.read(hex"0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f7965000000".toArray)
    val Success(bothInputsFilled) = oneInputFilled.update(
      tx2,
      outputIndex = 1,
      Some(Script.pay2wsh(Script.createMultiSigMofN(2, Seq(aliceKeyWitness.publicKey, bobKeyWitness.publicKey)))),
      Some(Script.createMultiSigMofN(2, Seq(aliceKeyWitness.publicKey, bobKeyWitness.publicKey)))
    )

    // Alice signs both inputs:
    val signedByAlice = {
      val Success(firstInputSigned) = bothInputsFilled.sign(aliceKeyNonWitness, 0)
      val Success(bothInputsSigned) = firstInputSigned.sign(aliceKeyWitness, 1)
      bothInputsSigned
    }

    // Bob signs both inputs:
    val signedByBob = {
      val Success(firstInputSigned) = signedByAlice.sign(bobKeyNonWitness, 0)
      val Success(bothInputsSigned) = firstInputSigned.sign(bobKeyWitness, 1)
      bothInputsSigned
    }

    // Finalize inputs and extract transaction:
    val Success(tx) = {
      // The first input is a non-witness 2-of-2 multi-sig:
      val redeemScript = Script.write(Script.createMultiSigMofN(2, Seq(aliceKeyNonWitness.publicKey, bobKeyNonWitness.publicKey)))
      val scriptSig = OP_0 +: signedByBob.inputs.head.partialSigs.values.map(sig => OP_PUSHDATA(ByteVector(sig))).toSeq :+ OP_PUSHDATA(redeemScript)
      val Success(firstInputFinalized) = signedByBob.finalize(inputIndex = 0, scriptSig)
      // The second input is a witness 2-of-2 multi-sig:
      val witnessScript = Script.write(Script.createMultiSigMofN(2, Seq(aliceKeyWitness.publicKey, bobKeyWitness.publicKey)))
      val scriptWitness = ScriptWitness(ByteVector.empty +: signedByBob.inputs(1).partialSigs.values.map(sig => ByteVector(sig)).toSeq :+ witnessScript)
      val Success(bothInputsFinalized) = firstInputFinalized.finalize(inputIndex = 1, scriptWitness)
      bothInputsFinalized.extract()
    }

    // Transaction is ready to be broadcast.
    Transaction.correctlySpends(tx, Seq(tx1, tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
```

### Wallet features

Bitcoin-lib provides and simple and complete implementation of BIP32 and BIP39.

#### HD Wallet (BIP32)

Let's play with the scala console and the first test vector from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

```shell
mvn scala:console

scala> import fr.acinq.bitcoin._
import fr.acinq.bitcoin._

scala> import scodec.bits._
import scodec.bits._

scala> import fr.acinq.bitcoin.DeterministicWallet
DeterministicWallet   DeterministicWalletSpec

scala> import fr.acinq.bitcoin.DeterministicWallet._
import fr.acinq.bitcoin.DeterministicWallet._

scala> val m = generate(hex"000102030405060708090a0b0c0d0e0f")
m: fr.acinq.bitcoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(m, xprv)
res1: String = xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi

scala> publicKey(m)
res2: fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2,873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508,0,m,0)

scala> encode(publicKey(m), xpub)
res3: String = xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8

scala> val priv = derivePrivateKey(m, KeyPath("0'/1/2'/2"))
priv: fr.acinq.bitcoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4,cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd,4,m/0h/1/2h/2,4001020172)

scala> encode(priv, xprv)
res5: String = xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334

scala> encode(publicKey(priv), xpub)
res6: String = xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV

scala> val k2 = derivePrivateKey(m, KeyPath("0'/1/2'"))
k2: fr.acinq.bitcoin.DeterministicWallet.ExtendedPrivateKey = ExtendedPrivateKey(cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca,04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0'/1/2',3203769081)

scala> val K2 = publicKey(k2)
K2: fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(ByteVector(33 bytes, 0x0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2),04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f,3,m/0'/1/2',3203769081)

scala> derivePublicKey(K2, KeyPath("2/1000000000"))
res6: fr.acinq.bitcoin.DeterministicWallet.ExtendedPublicKey = ExtendedPublicKey(ByteVector(33 bytes, 0x022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011),c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e,5,m/0'/1/2'/2/1000000000,3632322520)

scala> encode(derivePublicKey(K2, KeyPath("2/1000000000")), xpub)
res8: String = xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy
```

#### Mnemonic code (BIP39)

```shell
mvn scala:console

scala> import fr.acinq.bitcoin._
import fr.acinq.bitcoin._

scala> import scodec.bits._
import scodec.bits._

scala> import MnemonicCode._
import MnemonicCode._

scala> val mnemonics = toMnemonics(hex"77c2b00716cec7213839159e404db50d")
mnemonics: List[String] = List(jelly, better, achieve, collect, unaware, mountain, thought, cargo, oxygen, act, hood, bridge)

scala> val seed = toSeed(mnemonics, "TREZOR")
seed: scodec.bits.ByteVector = ByteVector(64 bytes, 0xb5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff)
```
