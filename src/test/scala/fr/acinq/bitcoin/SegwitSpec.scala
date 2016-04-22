package fr.acinq.bitcoin

import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class SegwitSpec extends FunSuite {
  test("tx serialization with witness") {
    // see https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Example
    val bin: BinaryData = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
    val tx = Transaction.read(bin, Protocol.PROTOCOL_VERSION | Transaction.SERIALIZE_TRANSACTION_WITNESS)

    assert(tx.witness == Seq(ScriptWitness.empty, ScriptWitness(
      Seq(
      BinaryData("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"),
      BinaryData("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
      )
    )))
    assert(BinaryData(Transaction.write(tx, Protocol.PROTOCOL_VERSION | Transaction.SERIALIZE_TRANSACTION_WITNESS)) == bin)
  }

  test("tx hash") {
    val tx = Transaction.read("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
    val hash: BinaryData = Transaction.hashForSigning(tx, 1, BinaryData("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"), SIGHASH_ALL, 600000000, 1)
    assert(hash == BinaryData("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"))

    val priv: BinaryData = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb901"
    val pub: BinaryData = Crypto.publicKeyFromPrivateKey(priv)
    val sig = BinaryData("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee")
    assert(Crypto.verifySignature(hash, sig, pub))

    val sigScript = BinaryData("4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01")
    val tx1 = tx.updateSigScript(0, sigScript)
    val tx2 = tx1.copy(witness = ScriptWitness.empty :: ScriptWitness((sig :+ SIGHASH_ALL.toByte) :: pub :: Nil) :: Nil)
    val bin: BinaryData = Transaction.write(tx2, Protocol.PROTOCOL_VERSION | Transaction.SERIALIZE_TRANSACTION_WITNESS)
    assert(bin === BinaryData("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"))
  }

  test("tx verification") {
    val tx = Transaction.read("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000", Protocol.PROTOCOL_VERSION | Transaction.SERIALIZE_TRANSACTION_WITNESS)
    val priv: BinaryData = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb901"
    val pub: BinaryData = Crypto.publicKeyFromPrivateKey(priv)
    val pubKeyScript = Script.write(OP_0 :: OP_PUSHDATA(Crypto.hash160(pub)) :: Nil)
    val runner = new Script.Runner(new Script.Context(tx, 1, 600000000), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(runner.verifyScripts(tx.txIn(1).signatureScript, pubKeyScript, tx.witness(1)))
  }

  test("tx p2pkh verification") {
    val tx1 = Transaction.read("01000000016e21b8c625d9955e48de0a6bbcd57b03624620a93536ddacabc19d024c330f04010000006a47304402204d34da42ad349a1c93e2bea2933c0bfb3dae6b06b01fa800315231139d3a8f8002204b5984f64b2564ff4fcdb67ae28ba94172681dead36e2ba64532795e30d4a030012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9700000000", Protocol.PROTOCOL_VERSION | Transaction.SERIALIZE_TRANSACTION_WITNESS)
    val tx2 = Transaction.read("0100000000010146cf03f5df6e9a36b1409e66791dea53b22cb330e51239ebd15f12d269e0adc40000000000ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9702483045022100b2b47d485f897c428b284eefc5f0e0bf854aac0ac9de21d5eb4984eec8bd21d702206ab2c763bf8c95e2aa924c628dd696adff659fed9cff1d7ed2bc617206ab06e5012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac01900000000", Protocol.PROTOCOL_VERSION | Transaction.SERIALIZE_TRANSACTION_WITNESS)
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }

  test("create p2wpkh tx") {
    val (Base58.Prefix.SecretKeySegnet, priv1) = Base58Check.decode("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT")
    val pub1: BinaryData = Crypto.publicKeyFromPrivateKey(priv1)
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressSegnet, Crypto.hash160(pub1))

    assert(address1 == "D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap")

    val pversion = Protocol.PROTOCOL_VERSION | Transaction.SERIALIZE_TRANSACTION_WITNESS

    // this is a standard tx that sends 0.5 BTC to D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap
    val tx1 = Transaction.read("0100000001b5bace8f333a944977dbd9eb0904c81baa1b4e5a5863f4948747663bef1ff89b010000006b48304502210093b6ed5b0f3c27752e5cc12f608e7dc4feff2c2e515eddc078b7ef87ad715d94022061c7247608cbacc96e9238f3b965180f38ffdefb368d7c6231d7bacc511d863e012103c628be57db41f24d84abd5a4d05bf2eb0c7ceb064066c2aeeedf2f05ffc7463cfeffffff02e0b8f505000000001976a914f01addb5b6ca589b176a173efb0e6a3a247ec8b288ac80f0fa02000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ac58460000", pversion)

    // now let's create a simple tx that spends tx1 and send 0.5 BTC to P2WPK output
    val tx2 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 1), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.5 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: Nil) :: Nil,
        lockTime = 0
      )
      Transaction.sign(tmp, Seq(SignData(tx1.txOut(1).publicKeyScript, priv1)))
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    println(BinaryData(Transaction.write(tx2, pversion)))
    // was published as 01000000016e21b8c625d9955e48de0a6bbcd57b03624620a93536ddacabc19d024c330f04010000006a47304402204d34da42ad349a1c93e2bea2933c0bfb3dae6b06b01fa800315231139d3a8f8002204b5984f64b2564ff4fcdb67ae28ba94172681dead36e2ba64532795e30d4a030012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9700000000
    // id c4ade069d2125fd1eb3912e530b32cb253ea1d79669e40b1369a6edff503cf46


    // and now we create a segwit tx that spends the P2WPK output
    val tx3 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.5 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: Nil) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)
      val hash = Transaction.hashForSigning(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount.amount, 1)
      val sig = Crypto.encodeSignature(Crypto.sign(hash, priv1.take(32))) :+ SIGHASH_ALL.toByte
      val witness = ScriptWitness(Seq(sig, pub1))
      tmp.copy(witness = Seq(witness))
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    println(BinaryData(Transaction.write(tx3, pversion)))
    // was published as 0100000000010146cf03f5df6e9a36b1409e66791dea53b22cb330e51239ebd15f12d269e0adc40000000000ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9702483045022100b2b47d485f897c428b284eefc5f0e0bf854aac0ac9de21d5eb4984eec8bd21d702206ab2c763bf8c95e2aa924c628dd696adff659fed9cff1d7ed2bc617206ab06e5012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac01900000000
    // id 4350becf32be78d09597fe597e948b4ce3b97ce9d9bafcdd1269fb14c792fbfb
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

    val pversion = Protocol.PROTOCOL_VERSION | Transaction.SERIALIZE_TRANSACTION_WITNESS

    // this is a standard tx that sends 0.5 BTC to D6YX7dpieYu8j1bV8B4RgksNmDk3sNJ4Ap
    val tx1 = Transaction.read("0100000001b5bace8f333a944977dbd9eb0904c81baa1b4e5a5863f4948747663bef1ff89b010000006b48304502210093b6ed5b0f3c27752e5cc12f608e7dc4feff2c2e515eddc078b7ef87ad715d94022061c7247608cbacc96e9238f3b965180f38ffdefb368d7c6231d7bacc511d863e012103c628be57db41f24d84abd5a4d05bf2eb0c7ceb064066c2aeeedf2f05ffc7463cfeffffff02e0b8f505000000001976a914f01addb5b6ca589b176a173efb0e6a3a247ec8b288ac80f0fa02000000001976a9140f66351d05269952302a607b4d6fb69517387a9788ac58460000", pversion)

    // now let's create a simple tx that spends tx1 and send 0.5 BTC to P2WSH output
    val tx2 = {
      // our script is a 2-of-2 multisig script
      val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 1), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.5 btc, OP_0 :: OP_PUSHDATA(Crypto.sha256(redeemScript)) :: Nil) :: Nil,
        lockTime = 0
      )
      Transaction.sign(tmp, Seq(SignData(tx1.txOut(1).publicKeyScript, priv1)))
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // and now we create a segwit tx that spends the P2WSH output
    val tx3 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = Seq.empty[Byte]) :: Nil,
        txOut = TxOut(0.5 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1)) :: Nil) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val hash = Transaction.hashForSigning(tmp, 0, pubKeyScript, SIGHASH_ALL, tx2.txOut(0).amount.amount, 1)
      val sig2 = Crypto.encodeSignature(Crypto.sign(hash, priv2.take(32))) :+ SIGHASH_ALL.toByte
      val sig3 = Crypto.encodeSignature(Crypto.sign(hash, priv3.take(32))) :+ SIGHASH_ALL.toByte
      val witness = ScriptWitness(Seq(
        BinaryData(""),
        sig2,
        sig3,
        pubKeyScript))
      tmp.copy(witness = Seq(witness))
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }
}
