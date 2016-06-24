package fr.acinq.bitcoin

import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class SegwitSpec extends FunSuite {
  val pversion = Protocol.PROTOCOL_VERSION

  test("tx serialization with witness") {
    // see https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Example
    val bin: BinaryData = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
    val tx = Transaction.read(bin, Protocol.PROTOCOL_VERSION)

    assert(tx.witness == Seq(ScriptWitness.empty, ScriptWitness(
      Seq(
      BinaryData("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"),
      BinaryData("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
      )
    )))
    assert(BinaryData(Transaction.write(tx, Protocol.PROTOCOL_VERSION)) == bin)
  }

  test("tx hash") {
    val tx = Transaction.read("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
    val hash: BinaryData = Transaction.hashForSigning(tx, 1, BinaryData("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"), SIGHASH_ALL, 600000000 satoshi, 1)
    assert(hash == BinaryData("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"))

    val priv: BinaryData = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb901"
    val pub: BinaryData = Crypto.publicKeyFromPrivateKey(priv)
    val sig = BinaryData("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee")
    assert(Crypto.verifySignature(hash, sig, pub))

    val sigScript = BinaryData("4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01")
    val tx1 = tx.updateSigScript(0, sigScript)
    val tx2 = tx1.copy(witness = ScriptWitness.empty :: ScriptWitness((sig :+ SIGHASH_ALL.toByte) :: pub :: Nil) :: Nil)
    val bin: BinaryData = Transaction.write(tx2, Protocol.PROTOCOL_VERSION)
    assert(bin === BinaryData("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"))
  }

  test("tx verification") {
    val tx = Transaction.read("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000", Protocol.PROTOCOL_VERSION)
    val priv: BinaryData = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb901"
    val pub: BinaryData = Crypto.publicKeyFromPrivateKey(priv)
    val pubKeyScript = Script.write(OP_0 :: OP_PUSHDATA(Crypto.hash160(pub)) :: Nil)
    val runner = new Script.Runner(new Script.Context(tx, 1, 600000000 satoshi), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(runner.verifyScripts(tx.txIn(1).signatureScript, pubKeyScript, tx.witness(1)))
  }

  test("segwit fixes tx malleability") {
    val tx1 = Transaction.read("010000000001011e0e457f710df0284a75773b5a8785bfde6f81ab6f5cbb81bbffdbd13c93cf3a0000000000ffffffff0180d54302000000001600140f66351d05269952302a607b4d6fb69517387a9702483045022100d1fe26c7e00b37b833c3973e7394d82d09934670e7d3995f6d8584dd7ef113930220700b4ce9195ddc086b0eaceb0cf7f7f1c89c8f6a5b1c11c7c8c02f4b3d0612ab012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac01900000000", pversion)
    assert(Transaction.isNotNull(tx1.witness))
    assert(tx1.txIn.find(!_.signatureScript.isEmpty).isEmpty)
    val tx2 = tx1.copy(witness = Seq(ScriptWitness.empty))
    assert(tx2.txid == tx1.txid)
  }

  test("tx p2pkh verification") {
    val tx1 = Transaction.read("01000000016e21b8c625d9955e48de0a6bbcd57b03624620a93536ddacabc19d024c330f04010000006a47304402204d34da42ad349a1c93e2bea2933c0bfb3dae6b06b01fa800315231139d3a8f8002204b5984f64b2564ff4fcdb67ae28ba94172681dead36e2ba64532795e30d4a030012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9700000000", Protocol.PROTOCOL_VERSION)
    val tx2 = Transaction.read("0100000000010146cf03f5df6e9a36b1409e66791dea53b22cb330e51239ebd15f12d269e0adc40000000000ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9702483045022100b2b47d485f897c428b284eefc5f0e0bf854aac0ac9de21d5eb4984eec8bd21d702206ab2c763bf8c95e2aa924c628dd696adff659fed9cff1d7ed2bc617206ab06e5012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac01900000000", Protocol.PROTOCOL_VERSION)
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }

  test("create p2wpkh tx") {
    val (Base58.Prefix.SecretKeySegnet, priv1) = Base58Check.decode("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT")
    val pub1: BinaryData = Crypto.publicKeyFromPrivateKey(priv1)
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressSegnet, Crypto.hash160(pub1))

    assert(address1 == "D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap")

    // this is a standard tx that sends 0.4 BTC to D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap
    val tx1 = Transaction.read("010000000001014d5a1833ddd78613408d66b0189e3171aa3b5d1a5b2df4392749d39291ea73cd0000000000feffffff02005a6202000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ac048b9800000000001976a914eb7c97a96fa9205b8a772d0c1d170e90a8a3098388ac02483045022100e2ccc1ab7e7e0c6bcbbdd4d9935448011b415fc1ec774416aa2760c3ae08431d022064ad6fd7c952df2b3f06a9cf94ddc9856c734c46ad43d0ab45d5ddf3b7deeef0012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019ae590000", pversion)

    // now let's create a simple tx that spends tx1 and send 0.39 BTC to P2WPK output
    val tx2 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.39 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: Nil) :: Nil,
        lockTime = 0
      )
      Transaction.sign(tmp, Seq(SignData(tx1.txOut(0).publicKeyScript, priv1)), randomize = false)
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == BinaryData("3acf933cd1dbffbb81bb5c6fab816fdebf85875a3b77754a28f00d717f450e1e"))
    // this tx was published on segnet as 3acf933cd1dbffbb81bb5c6fab816fdebf85875a3b77754a28f00d717f450e1e

    // and now we create a segwit tx that spends the P2WPK output
    val tx3 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.38 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: Nil) :: Nil,
        lockTime = 0
      )
      // mind this: the pubkey script used for signing is not the prevout pubscript (which is just a push
      // of the pubkey hash), but the actual script that is evaluated by the script engine
      val pubKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)
      val sig = Transaction.signInput(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, 1, priv1, randomize = false)
      val witness = ScriptWitness(Seq(sig, pub1))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == BinaryData("a474219df20b95210b8dac45bb5ed49f0979f8d9b6c17420f3e50f6abc071af8"))
    // this tx was published on segnet as a474219df20b95210b8dac45bb5ed49f0979f8d9b6c17420f3e50f6abc071af8
  }

  test("create p2wsh tx") {
    val (Base58.Prefix.SecretKeySegnet, priv1) = Base58Check.decode("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT")
    val pub1: BinaryData = Crypto.publicKeyFromPrivateKey(priv1)
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressSegnet, Crypto.hash160(pub1))
    assert(address1 == "D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap")

    val (Base58.Prefix.SecretKeySegnet, priv2) = Base58Check.decode("QUpr3G5ia7K7txSq5k7QpgTfNy33iTQWb1nAUgb77xFesn89xsoJ")
    val pub2: BinaryData = Crypto.publicKeyFromPrivateKey(priv2)

    val (Base58.Prefix.SecretKeySegnet, priv3) = Base58Check.decode("QX3AN7b3WCAFaiCvAS2UD7HJZBsFU6r5shjfogJu55411hAF3BVx")
    val pub3: BinaryData = Crypto.publicKeyFromPrivateKey(priv3)

    // this is a standard tx that sends 0.5 BTC to D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap
    val tx1 = Transaction.read("010000000240b4f27534e9d5529e67e52619c7addc88eff64c8e7afc9b41afe9a01c6e2aea010000006b48304502210091aed7fe956c4b2471778bfef5a323a96fee21ec6d73a9b7f363beaad135c5f302207f63b0ffc08fd905cdb87b109416c2d6d8ec56ca25dd52529c931aa1154277f30121037cb5789f1ca6c640b6d423ef71390e0b002da81db8fad4466bf6c2fdfb79a24cfeffffff6e21b8c625d9955e48de0a6bbcd57b03624620a93536ddacabc19d024c330f04010000006a47304402203fb779df3ae2bf8404e6d89f83af3adee0d0a0c4ec5a01a1e88b3aa4313df6490220608177ca82cf4f7da9820a8e8bf4266ccece9eb004e73926e414296d0635d7c1012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019feffffff0280f0fa02000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ace06d9800000000001976a91457572594090c298721e8dddcec3ac1ec593c6dcc88ac205a0000", pversion)

    // now let's create a simple tx that spends tx1 and send 0.5 BTC to a P2WSH output
    val tx2 = {
      // our script is a 2-of-2 multisig script
      val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.49 btc, OP_0 :: OP_PUSHDATA(Crypto.sha256(redeemScript)) :: Nil) :: Nil,
        lockTime = 0
      )
      Transaction.sign(tmp, Seq(SignData(tx1.txOut(0).publicKeyScript, priv1)), randomize = false)
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == BinaryData("9d896b6d2b8fc9665da72f5b1942f924a37c5c714f31f40ee2a6c945f74dd355"))
    // this tx was published on segnet as 9d896b6d2b8fc9665da72f5b1942f924a37c5c714f31f40ee2a6c945f74dd355

    // and now we create a segwit tx that spends the P2WSH output
    val tx3 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.48 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: Nil) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val hash = Transaction.hashForSigning(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount, 1)
      val sig2 = Crypto.encodeSignature(Crypto.sign(hash, priv2.take(32), randomize = false)) :+ SIGHASH_ALL.toByte
      val sig3 = Crypto.encodeSignature(Crypto.sign(hash, priv3.take(32), randomize = false)) :+ SIGHASH_ALL.toByte
      val witness = ScriptWitness(Seq(BinaryData.empty, sig2, sig3, pubKeyScript))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == BinaryData("943e07f0c66a9766d0cec81d65a03db4157bc0bfac4d36e400521b947be55aeb"))
    // this tx was published on segnet as 943e07f0c66a9766d0cec81d65a03db4157bc0bfac4d36e400521b947be55aeb
  }

  test("create p2pkh embedded in p2sh") {
    val (Base58.Prefix.SecretKeySegnet, priv1) = Base58Check.decode("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT")
    val pub1: BinaryData = Crypto.publicKeyFromPrivateKey(priv1)

    // p2wpkh script
    val script = Script.write(OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: Nil)

    // which we embeed into a standard p2sh script
    val p2shaddress = Base58Check.encode(Base58.Prefix.ScriptAddressSegnet, Crypto.hash160(script))
    assert(p2shaddress === "MDbNMghDbaaizHz8pSgMqu9qJXvKwouqkM")


    // this tx send 0.5 btc to our p2shaddress
    val tx = Transaction.read("010000000175dd435bf25e5d77567272f7d6eefcf37b7156b78bb233490140d6fa7545cfca010000006a47304402206e601a482b301141cb3a1712c18729fa1f1731fce5c4205ac9d344af38bb24bf022003fe70edcbd1a5b3957b3c939e583739eadb8de8d3d2cc2ad2903b19c991cb80012102ba2558223d7cd5df2d8decc4506a62ccaa96159f685360335c280952b25e7adefeffffff02692184df000000001976a9148b3ee15d631122010d31e1774aa318ca9ca8b67088ac80f0fa020000000017a9143e73638f202bb880a28e8df1946adc3058227d11878c730000", pversion)

    // let's spend it:

    val tx1 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx.hash, 1), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.49 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: Nil) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)
      val hash = Transaction.hashForSigning(tmp, 0, pubKeyScript, SIGHASH_ALL, tx.txOut(1).amount, 1)
      val sig = Crypto.encodeSignature(Crypto.sign(hash, priv1.take(32), randomize = false)) :+ SIGHASH_ALL.toByte
      val witness = ScriptWitness(Seq(sig, pub1))
      tmp.updateSigScript(0, OP_PUSHDATA(script) :: Nil).updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx1, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx1.txid === BinaryData("98f5668176b0c1b14653f96f71987fd325c3d46b9efb677ab0606ea5555791d5"))
    // this tx was published on segnet as 98f5668176b0c1b14653f96f71987fd325c3d46b9efb677ab0606ea5555791d5
  }
}
