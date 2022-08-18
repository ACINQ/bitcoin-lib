package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin.scalacompat.Crypto.PrivateKey
import fr.acinq.bitcoin.{Base58, Base58Check, ScriptFlags, SigHash, SigVersion}
import fr.acinq.bitcoin.scalacompat.Crypto.PrivateKey
import org.scalatest.FunSuite
import scodec.bits._

class SegwitSpec extends FunSuite {
  val pversion: Int = Protocol.PROTOCOL_VERSION

  test("tx serialization with witness") {
    // see https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Example
    val bin = hex"01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
    val tx = Transaction.read(bin.toArray, Protocol.PROTOCOL_VERSION)

    assert(tx.txIn.map(_.witness) == Seq(ScriptWitness.empty, ScriptWitness(
      Seq(
        hex"304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01",
        hex"025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
      )
    )))
    assert(tx.bin == bin)
  }

  test("tx hash") {
    val tx = Transaction.read("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
    val hash: ByteVector = Transaction.hashForSigning(tx, 1, hex"76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac", SigHash.SIGHASH_ALL, 600000000 sat, 1)
    assert(hash == hex"c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")

    val priv = PrivateKey(hex"619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb901")
    val pub = priv.publicKey
    val sig = hex"304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
    assert(Crypto.verifySignature(hash, Crypto.der2compact(sig), pub))

    val sigScript = hex"4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01"
    val tx1 = tx.updateSigScript(0, sigScript)
    val tx2 = tx1.updateWitness(1, ScriptWitness((sig :+ SigHash.SIGHASH_ALL.toByte) :: pub.value :: Nil))
    assert(tx2.toString === "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000")
  }

  test("tx verification") {
    val tx = Transaction.read("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000", Protocol.PROTOCOL_VERSION)
    val priv = PrivateKey(hex"619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb901")
    val pub = priv.publicKey
    val pubKeyScript = Script.write(Script.pay2wpkh(pub))
    val runner = new Script.Runner(Script.Context(tx, 1, 600000000 sat), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(runner.verifyScripts(tx.txIn(1).signatureScript, pubKeyScript, tx.txIn(1).witness))
  }

  test("segwit fixes tx malleability") {
    val tx1 = Transaction.read("010000000001011e0e457f710df0284a75773b5a8785bfde6f81ab6f5cbb81bbffdbd13c93cf3a0000000000ffffffff0180d54302000000001600140f66351d05269952302a607b4d6fb69517387a9702483045022100d1fe26c7e00b37b833c3973e7394d82d09934670e7d3995f6d8584dd7ef113930220700b4ce9195ddc086b0eaceb0cf7f7f1c89c8f6a5b1c11c7c8c02f4b3d0612ab012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac01900000000", pversion)
    assert(tx1.hasWitness)
    assert(tx1.txIn.forall(_.signatureScript.isEmpty))
    val tx2 = tx1.updateWitnesses(Seq(ScriptWitness.empty))
    assert(tx2 != tx1)
    assert(tx2.txid == tx1.txid)
  }

  test("tx p2pkh verification") {
    val tx1 = Transaction.read("01000000016e21b8c625d9955e48de0a6bbcd57b03624620a93536ddacabc19d024c330f04010000006a47304402204d34da42ad349a1c93e2bea2933c0bfb3dae6b06b01fa800315231139d3a8f8002204b5984f64b2564ff4fcdb67ae28ba94172681dead36e2ba64532795e30d4a030012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac019ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9700000000", Protocol.PROTOCOL_VERSION)
    val tx2 = Transaction.read("0100000000010146cf03f5df6e9a36b1409e66791dea53b22cb330e51239ebd15f12d269e0adc40000000000ffffffff0180f0fa02000000001600140f66351d05269952302a607b4d6fb69517387a9702483045022100b2b47d485f897c428b284eefc5f0e0bf854aac0ac9de21d5eb4984eec8bd21d702206ab2c763bf8c95e2aa924c628dd696adff659fed9cff1d7ed2bc617206ab06e5012102edc343e7c422e94cca4c2a87a4f7ce54594c1b68682bbeefa130295e471ac01900000000", Protocol.PROTOCOL_VERSION)
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }

  test("create p2wpkh tx") {
    val priv1 = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.value).toArray)

    assert(address1 == "mp4eLFx7CpifAJxnvCZ3FmqKsh9dQmi5dA")

    // this is a standard tx that sends 0.04 BTC to mp4eLFx7CpifAJxnvCZ3FmqKsh9dQmi5dA
    val tx1 = Transaction.read("02000000000101516508384a3e006340f1ea700eb3635330beed5d94c7b460b6b495eb1593d55c0100000023220020a5fdf5b5f2c592362b78a50997821964b39dd90476c6e1f3e97e79acb134ca3bfdffffff0200093d00000000001976a9145dbf52b8d7af4fb5f9b75b808f0a8284493531b388aca005071d0000000017a914d77e5f7ca4d9f05dc4f25dc0aa1391f0e901bdfc87040047304402207bfb18327be173512f38bd4120b8f02545321ecc6105a852cbc25b1de687ba570220705a1225d8a8e0fbd4b35f3bc38a2840706f8524e8dc6f0151746aeff14033ce014730440220486925fb0495442e4ccb1b711692af7057d4db24f8775b5dfa3f8c74992081f102203beae7d96423e0c66b7b5f8919a5f3ad89a42dc4303f37201e4e596909478357014752210245119449d07c16992c148e3b33f1395ee05c936fc510d9fae83417f8e1901f922103eb03f67b56c88bccff90b76182c08556eac9ebc5a0efee8669bef69ae6d4ea5752ae75bb2300", pversion)

    // now let's create a simple tx that spends tx1 and send 0.039 BTC to P2WPK output
    val tx2 = {
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty, witness = ScriptWitness.empty) :: Nil,
        txOut = TxOut(0.039 btc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      val sig = Transaction.signInput(tmp, 0, tx1.txOut(0).publicKeyScript, SigHash.SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, priv1)
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == ByteVector32(hex"f25b3fecc9652466926237d96e4bc7ee2c984051fe48e61417aba218af5570c3"))
    // this tx was published on testnet as f25b3fecc9652466926237d96e4bc7ee2c984051fe48e61417aba218af5570c3

    // and now we create a testnet tx that spends the P2WPK output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty, witness = ScriptWitness.empty) :: Nil,
        txOut = TxOut(0.038 btc, Script.pay2wpkh(pub1)) :: Nil, // we reuse the same output script but if could be anything else
        lockTime = 0
      )
      // mind this: the pubkey script used for signing is not the prevout pubscript (which is just a push
      // of the pubkey hash), but the actual script that is evaluated by the script engine, in this case a PAY2PKH script
      val pubKeyScript = Script.pay2pkh(pub1)
      val sig = Transaction.signInput(tmp, 0, pubKeyScript, SigHash.SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)
      val witness = ScriptWitness(Seq(sig, pub1.value))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == ByteVector32(hex"739e7cba97af259d2c089690adea00aa78b1c8d7995aa9377be58fe5332378aa"))
    // this tx was published on testnet as 739e7cba97af259d2c089690adea00aa78b1c8d7995aa9377be58fe5332378aa
  }

  test("create p2wsh tx") {
    val priv1 = PrivateKey.fromBase58("cV5oyXUgySSMcUvKNdKtuYg4t4NTaxkwYrrocgsJZuYac2ogEdZX", Base58.Prefix.SecretKeyTestnet)._1
    val pub1 = priv1.publicKey
    val address1 = Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, Crypto.hash160(pub1.value).toArray)

    assert(address1 == "mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ")

    val priv2 = PrivateKey.fromBase58("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs", Base58.Prefix.SecretKeyTestnet)._1
    val pub2 = priv2.publicKey

    val priv3 = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
    val pub3 = priv3.publicKey

    // this is a standard tx that sends 0.05 BTC to mkNdbutRYE3me7wvbwvvJ8XQwbzi56sneZ
    val tx1 = Transaction.read("020000000001016ecc08b535a0c774234419dee508867ace1535a0d256d6b2aa19942441777336000000002322002073bb471aa121fbdd95942eabb5e665d66e71542e6e075c8392cd0df72a075b72fdffffff02803823030000000017a914d3c15be7951c9de644bdf9e22dcbcb77550c4ae487404b4c00000000001976a9143545b2a6659dbe5bdf841d1158135be184d81d3688ac0400473044022041cac92405e4e3215c2f9c27a67ff0792c8fb76e4182023fed081f541f4563e002203bd04d4d810ef8074aeb26a19e01e1ee1a40ad83e4d0ac2c614b8cb22825d2ae0147304402204c947b46ea480419c04098a56a5219bb1f491b07e12926fb6f304132a1f1e29e022078cc9f004c74d6c3c2b2dfcca6385d2fabe44d4eadb027a0d764e1ab9d7f09190147522102be608bf8904326b4d0ec9346aa348773fe51ee70338849acd2dd710b73bf611a2103627c19e40f67c5ee8b44df85ee911b7e978869fa5a3de1d972a461f47ea349e452ae90bb2300", pversion)

    // now let's create a simple tx that spends tx1 and send 0.5 BTC to a P2WSH output
    val tx2 = {
      // our script is a 2-of-2 multisig script
      val redeemScript = Script.createMultiSigMofN(2, Seq(pub2, pub3))
      val tmp = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx1.hash, 1), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.049 btc, Script.pay2wsh(redeemScript)) :: Nil,
        lockTime = 0
      )
      val sig = Transaction.signInput(tmp, 0, tx1.txOut(1).publicKeyScript, SigHash.SIGHASH_ALL, 0 sat, SigVersion.SIGVERSION_BASE, priv1)
      tmp.updateSigScript(0, OP_PUSHDATA(sig) :: OP_PUSHDATA(priv1.publicKey) :: Nil)
      //Transaction.sign(tmp, Seq(SignData(tx1.txOut(1).publicKeyScript, priv1)))
    }
    Transaction.correctlySpends(tx2, Seq(tx1), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx2.txid == ByteVector32(hex"2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9"))
    // this tx was published on testnet as 2f8360a06a31ca642d717b1857aa86b3306fc554fa9c437d88b4bc61b7f2b3e9

    // and now we create a testnet tx that spends the P2WSH output
    val tx3 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx2.hash, 0), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.048 btc, Script.pay2wpkh(pub1)) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.write(Script.createMultiSigMofN(2, Seq(pub2, pub3)))
      val sig2 = Transaction.signInput(tmp, 0, pubKeyScript, SigHash.SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv2)
      val sig3 = Transaction.signInput(tmp, 0, pubKeyScript, SigHash.SIGHASH_ALL, tx2.txOut(0).amount, SigVersion.SIGVERSION_WITNESS_V0, priv3)
      val witness = ScriptWitness(Seq(ByteVector.empty, sig2, sig3, pubKeyScript))
      tmp.updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx3, Seq(tx2), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx3.txid == ByteVector32(hex"4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a"))
    // this tx was published on testnet as 4817f79def9d9f559ddaa636f0c196e79f31bc959feead77b4151733114c652a
  }

  test("create p2pkh embedded in p2sh") {
    val priv1 = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet)._1
    val pub1 = priv1.publicKey

    // p2wpkh script
    val script = Script.write(Script.pay2wpkh(pub1))

    // which we embed into a standard p2sh script
    val p2shaddress = Base58Check.encode(Base58.Prefix.ScriptAddressTestnet, Crypto.hash160(script).toArray)
    assert(p2shaddress === "2NB3GUVxBF3P7NLMkSGNai33mWkM35ht1Xj")

    // this tx send 0.05 btc to our p2shaddress
    val tx = Transaction.read("02000000000101d9ee0034f9ae4fac7a4017d78e26e1c492d507e16f3535ecbc2ea72cb1c4c6f501000000232200208a15b02dab825f2a4b60b58a7c8591c659a3eb18765fd9d926332c0cea574e2ffdffffff02d292e4000000000017a914aefbc2c20e0c312a616cf7c4ebbacc5c9a04432787404b4c000000000017a914c32f5922344dbe1abd4fb1744b560b5d1875353987040047304402205fbba2ab917efc23209fe04086fb5f714e527d088e2a5ec19590ec4b566a8c2d02206607f3e42eaff5d30dd6297dcb4d48300a75819a358c0bc20396e393ab1594260147304402206a0df35cb8fc58fb21b111d432abc7f9f74836ad1e35c63be2f0c772d4a2ce49022076c4c96a7a9d18577a5e762a3dc3e4b728fd950284c133eb3147707b9181f90b01475221039c40944fe4f90f46760621a1ca66d3141f7e81ccccfa2cf4550fdb9b432c52ed2102976af59e7b61fb3c7a6a2553d7b030a5e292fdda6eba439b4a24af494b3475c752aebebb2300", pversion)

    // let's spend it:

    val tx1 = {
      val tmp: Transaction = Transaction(version = 1,
        txIn = TxIn(OutPoint(tx.hash, 1), sequence = 0xffffffffL, signatureScript = ByteVector.empty) :: Nil,
        txOut = TxOut(0.049 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1.value)) :: Nil) :: Nil,
        lockTime = 0
      )
      val pubKeyScript = Script.pay2pkh(pub1)
      val sig = Transaction.signInput(tmp, 0, pubKeyScript, SigHash.SIGHASH_ALL, tx.txOut(1).amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)
      val witness = ScriptWitness(Seq(sig, pub1.value))
      tmp.updateSigScript(0, OP_PUSHDATA(script) :: Nil).updateWitness(0, witness)
    }

    Transaction.correctlySpends(tx1, Seq(tx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    assert(tx1.txid === ByteVector32(hex"4807cb10f50df84acd7766245133f902d22d91b7e8bfe77c4bbcb0cf9b017a86"))
    // this tx was published on testnet as 4807cb10f50df84acd7766245133f902d22d91b7e8bfe77c4bbcb0cf9b017a86
  }
}
