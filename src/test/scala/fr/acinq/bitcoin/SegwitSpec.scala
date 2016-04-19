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
}
