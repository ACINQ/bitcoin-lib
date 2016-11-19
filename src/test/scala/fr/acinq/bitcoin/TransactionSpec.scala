package fr.acinq.bitcoin

import java.io.ByteArrayOutputStream
import java.util

import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.{FlatSpec, Matchers}
import Protocol._

@RunWith(classOf[JUnitRunner])
class TransactionSpec extends FlatSpec with Matchers {
  "Bitcoins library" should "create and sign transaction" in {
    val srcTx = fromHexString("dcd82df7b26f0eacd226b8fbd366672c854284ba8080f79e1307138c7f1a1f6d".sliding(2, 2).toList.reverse.mkString("")) // for some reason it has to be reversed
    val amount = 9000000 // amount in satoshi
    val vout = 0 // output index
    val destAdress = fromHexString("76a914c622640075eaeda95a5ac26fa05a0b894a3def8c88ac")
    val out = new ByteArrayOutputStream()
    writeUInt32(1, out) //version
    writeVarint(1, out) // nb of inputs
    out.write(srcTx) // tx in id
    writeUInt32(vout, out)
    writeScript(fromHexString("76a914ea2902457015b386bd2323b2b99591b96138d62a88ac"), out) //scriptPubKey of prev tx for signing
    writeUInt32(0xffffffff, out) // sequence
    writeVarint(1, out) // number of outputs
    writeUInt64(amount, out)
    writeScript(destAdress, out) //output script
    writeUInt32(0, out)
    writeUInt32(1, out) // hash code type
    val serialized = out.toByteArray
    val hashed = Crypto.hash256(serialized)
    val pkey_encoded = Base58.decode("92f9274aR3s6zd1vuAgxquv4KP5S5thJadF3k54NHuTV4fXL1vW")
    val pkey = pkey_encoded.slice(1, pkey_encoded.size - 4)
    val (r, s) = Crypto.sign(hashed, pkey)
    val sig = Crypto.encodeSignature(r, s) // DER encoded
    val sigOut = new ByteArrayOutputStream()
    writeUInt8(sig.length + 1, sigOut) // +1 because of the hash code
    sigOut.write(sig.toArray)
    writeUInt8(1, sigOut) // hash code type
    val pub = Crypto.publicKeyFromPrivateKey(pkey)
    writeUInt8(pub.length, sigOut)
    sigOut.write(pub)
    val sigScript = sigOut.toByteArray

    val signedOut = new ByteArrayOutputStream()
    writeUInt32(1, signedOut) //version
    writeVarint(1, signedOut) // nb of inputs
    signedOut.write(srcTx) // tx in id
    writeUInt32(vout, signedOut) // output index
    writeScript(sigScript, signedOut)
    writeUInt32(0xffffffff, signedOut) // sequence
    writeVarint(1, signedOut) // number of outputs
    writeUInt64(amount, signedOut) // amount in satoshi
    writeScript(destAdress, signedOut) //output script
    writeUInt32(0, signedOut)
    assert(toHexString(signedOut.toByteArray) === "01000000016d1f1a7f8c1307139ef78080ba8442852c6766d3fbb826d2ac0e6fb2f72dd8dc000000008b483045022100bdd23d0f98a4173a64fa432b8bf4ac41261a671f2c6c690d57ac839866d78bb202207bddb87ca95c9cef45de30a75144e5513571aa7938635b9e051b1c20f01088a60141044aec194c55c97f4519535f50f5539c6915045ecb79a36281dee6db55ffe1ad2e55f4a1c0e0950d3511e8f205b45cafa348a4a2ab2359246cb3c93f6532c4e8f5ffffffff0140548900000000001976a914c622640075eaeda95a5ac26fa05a0b894a3def8c88ac00000000")
  }
  it should "read and write transactions" in {
    val hex = "0100000003864d5e5ec82c9e6f4ac52b8fa47b77f8616bbc26fcf668432c097c5add169584010000006a47304402203be0cff1faacadce3b02d615a8ac15532f9a90bd30e109eaa3e01bfa3a97d90b0220355f3bc382e35b9cae24e5d674f200b289bb948675ce1b5c931029ccb23ae836012102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffffd587b10688e6d56225dd4dc488b74229a353e4613cbe1deadaef52b56616baa9000000008b483045022100ab98145e8526b32e821beeaed41a98da68c3c75ee13c477ee0e3d66a626217e902204d015af2e7dba834bbe421dd0b1353a1060dafee58c284dd763e07639858f9340141043ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87d53dfcba3525369fdb248e60233fdf6df0a8183a6dd5699c9a6f5c537367c627ffffffff94a162b4aab080a09fa982a5d7f586045ba2a4c653c98ff47b952d43c25b45fd000000008a47304402200e0c0223d169282a48731b58ff0673c00205deb3f3f4f28d99b50730ada1571402202fa9f051762d8e0199791ea135df1f393578c1eea530bec00fa16f6bba7e3aa3014104626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c21364ed5dbe97c9c6e2be40fff40c31f8561a9dee015146fe59ecf68b8a377292c72ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000"
    val tx = Transaction.read(fromHexString(hex))
    assert(toHexString(Transaction.write(tx)) === hex)
  }
  it should "create and verify pay2pk transactions with 1 input/1 output" in {
    val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
    val amount = 10000 satoshi
    val (_, privateKey) = Base58Check.decode("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp")

    val previousTx = Transaction.read("0100000001b021a77dcaad3a2da6f1611d2403e1298a902af8567c25d6e65073f6b52ef12d000000006a473044022056156e9f0ad7506621bc1eb963f5133d06d7259e27b13fcb2803f39c7787a81c022056325330585e4be39bcf63af8090a2deff265bc29a3fb9b4bf7a31426d9798150121022dfb538041f111bb16402aa83bd6a3771fa8aa0e5e9b0b549674857fafaf4fe0ffffffff0210270000000000001976a91415c23e7f4f919e9ff554ec585cb2a67df952397488ac3c9d1000000000001976a9148982824e057ccc8d4591982df71aa9220236a63888ac00000000")
    // create a transaction where the sig script is the pubkey script of the tx we want to redeem
    // the pubkey script is just a wrapper around the pub key hash
    // what it means is that we will sign a block of data that contains txid + from + to + amount

    // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
    val tx1 = Transaction(
      version = 1L,
      txIn = List(
        TxIn(
          OutPoint(previousTx, 0),
          signatureScript = previousTx.txOut(0).publicKeyScript,
          sequence = 0xFFFFFFFFL)
      ),
      txOut = List(
        TxOut(
          amount = amount,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(to)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil))
      ),
      lockTime = 0L
    )

    // step #2: serialize transaction and add SIGHASHTYPE
    val serializedTx1AndHashType = Transaction.write(tx1) ++ writeUInt32(1)

    // step #3: hash the result
    val hashed = Crypto.hash256(serializedTx1AndHashType)

    // step #4: sign transaction hash
    val (r, s) = Crypto.sign(hashed, privateKey.take(32))
    val sig = Crypto.encodeSignature(r, s) // DER encoded

    // this is the public key that is associated to the private key we used for signing
    val publicKey = Crypto.publicKeyFromPrivateKey(privateKey)
    // we check that is really is the public key that is encoded in the address the previous tx was paid to
    val providedHash = Base58Check.decode("mhW1BQDyhbTsnHEuB1n7yuj9V81TbeRfTY")._2
    val computedHash = Crypto.hash160(publicKey)
    assert(providedHash == computedHash)

    // step #5: now we replace the sigscript with sig + public key, and we get what would be sent to the btc network
    val tx2 = tx1.copy(txIn = List(
      TxIn(
        OutPoint(previousTx, 0),
        signatureScript = Script.write(OP_PUSHDATA(sig :+ 1.toByte) :: OP_PUSHDATA(publicKey) :: Nil),
        sequence = 0xFFFFFFFFL
      )
    ))

    // check signature
    assert(Crypto.verifySignature(hashed, sig, publicKey))

    // check script
    Transaction.correctlySpends(tx2, Seq(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
  }
  // same as above, but using Transaction.sign() instead of signing the tx manually
  it should "create and verify pay2pk transactions with 1 input/1 output using helper method" in {
    val to = "mi1cMMSL9BZwTQZYpweE1nTmwRxScirPp3"
    val amount = 10000 satoshi

    val (_, privateKey) = Base58Check.decode("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp")

    val previousTx = Transaction.read("0100000001b021a77dcaad3a2da6f1611d2403e1298a902af8567c25d6e65073f6b52ef12d000000006a473044022056156e9f0ad7506621bc1eb963f5133d06d7259e27b13fcb2803f39c7787a81c022056325330585e4be39bcf63af8090a2deff265bc29a3fb9b4bf7a31426d9798150121022dfb538041f111bb16402aa83bd6a3771fa8aa0e5e9b0b549674857fafaf4fe0ffffffff0210270000000000001976a91415c23e7f4f919e9ff554ec585cb2a67df952397488ac3c9d1000000000001976a9148982824e057ccc8d4591982df71aa9220236a63888ac00000000")

    // create a transaction where the sig script is the pubkey script of the tx we want to redeem
    // the pubkey script is just a wrapper around the pub key hash
    // what it means is that we will sign a block of data that contains txid + from + to + amount

    // step  #1: creation a new transaction that reuses the previous transaction's output pubkey script
    val tx1 = Transaction(
      version = 1L,
      txIn = List(
        TxIn(
          OutPoint(previousTx, 0),
          signatureScript = Array.empty[Byte],
          sequence = 0xFFFFFFFFL)
      ),
      txOut = List(
        TxOut(
          amount = amount,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(to)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil))
      ),
      lockTime = 0L
    )

    // step #2: sign the tx
    val tx2 = Transaction.sign(tx1, List(SignData(previousTx.txOut(0).publicKeyScript, privateKey)))

    // redeem the tx
    Transaction.correctlySpends(tx2, Seq(previousTx), ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
  }
  it should "create and verify sign pay2pk transactions with multiple inputs and outputs" in {
    val destAddress = "moKHwpsxovDtfBJyoXpof21vvWooBExutV"
    val destAmount = 3000000 satoshi

    val changeAddress = "mvHPesWqLXXy7hntNa7vbAoVwqN5PnrwJd"
    val changeAmount = 1700000 satoshi

    val previousTx = List(
      Transaction.read("0100000001bb4f5a244b29dc733c56f80c0fed7dd395367d9d3b416c01767c5123ef124f82000000006b4830450221009e6ed264343e43dfee2373b925915f7a4468e0bc68216606e40064561e6c097a022030f2a50546a908579d0fab539d5726a1f83cfd48d29b89ab078d649a8e2131a0012103c80b6c289bf0421d010485cec5f02636d18fb4ed0f33bfa6412e20918ebd7a34ffffffff0200093d00000000001976a9145dbf52b8d7af4fb5f9b75b808f0a8284493531b388acf0b0b805000000001976a914807c74c89592e8a260f04b5a3bc63e7bef8c282588ac00000000"),
      Transaction.read("0100000001345b2a5f872f73de2c4f32e4c28834832ba4c2ce5e54af1e8b897f49766141af00000000fdfe0000483045022100e5a3c850d7cb8776bfbd3fa4b24ce9bb3514fe96a922449dd14c03f5fa04d6ad022035710c6b9c2922c7b8de02fb674cb61e2c18ea439b190b4f55c14fad1ed89eb801483045022100ec6b1ea37cc5694312f7d5fe72280ef21688d11e00f307fdcc1eff30718e30560220542e02c32e3e392cce7adfc287c72f7f1e51ca73980505c2bebcf0b7b441ff90014c6952210394d30868076ab1ea7736ed3bdbec99497a6ad30b25afd709cdf3804cd389996a21032c58bc9615a6ff24e9132cef33f1ef373d97dc6da7933755bc8bb86dbee9f55c2102c4d72d99ca5ad12c17c9cfe043dc4e777075e8835af96f46d8e3ccd929fe192653aeffffffff0100350c00000000001976a914801d5eb10d2c1513ba1960fd8893f0ddbbe33bb388ac00000000")
    )

    val keys = List(
      SignData(previousTx(0).txOut(0).publicKeyScript, Base58Check.decode("cV7LGVeY2VPuCyCSarqEqFCUNig2NzwiAEBTTA89vNRQ4Vqjfurs")._2),
      SignData(previousTx(1).txOut(0).publicKeyScript, Base58Check.decode("93NJN4mhL21FxRbfHZJ2Cou1YnrJmWNkujmZxeT7CPKauJkGv5g")._2)
    )

    // create a tx with empty input signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = previousTx.map(tx => TxIn(OutPoint(tx, 0), sequence = 0xFFFFFFFFL, signatureScript = Array.empty[Byte])),
      txOut = List(
        TxOut(
          amount = destAmount,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(destAddress)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)),
        TxOut(
          amount = changeAmount,
          publicKeyScript = Script.write(OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(changeAddress)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil))),
      lockTime = 0L
    )

    val tx1 = Transaction.sign(tx, keys)
    assert(toHexString(Transaction.write(tx1)) === "01000000026c8a0bb4fef409509800066578a718e9a771082d94e96e0885a4b6a15b720c02000000006b483045022100e5510a2f15f03788ee2aeb2115edc96089596e3a0f0c1b1abfbbf069f4beedb802203faf6ec92a5a4ed2ce5fd42621be99746b57eca0eb46d322dc076080338b6c5a0121030533e1d2e9b7576fef26de1f34d67887158b7af1b040850aab6024b07925d70affffffffaf01f14881716b8acb062c33e7a66fc71e77bb2e4359b1f91b959aeb4f8837f1000000008b483045022100d3e5756f36e39a801c71c406124b3e0a66f0893a7fea46c69939b84715137c40022070a0e96e37c0a8e8c920e84fc63ed1914b4cef114a027f2d027d0a4a04b0b52d0141040081a4cce4c497d51d2f9be2d2109c00cbdef252185ca23074889604ace3504d73fd5f5aaac6423b04e776e467a948e1e79cb8793ded5f4b59c730c4460a0f86ffffffff02c0c62d00000000001976a914558c6b340f5abd22bf97b15cbc1483f8f1b54f5f88aca0f01900000000001976a914a1f93b5b00f9f5e8ade5549b58ed06cdc5c8203e88ac00000000")

    // now check that we can redeem this tx
    Transaction.correctlySpends(tx1, previousTx, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
    // the id of this tx on testnet is 882e971dbdb7b762cd07e5db016d3c81267ec5233186a31e6f40457a0a56a311
  }

  it should "sign a 3-to-2 transaction with helper method" in {

    val previousTx = List(
      Transaction.read("0100000001cec6dd9f7ddc640f7bb54daf5623040532b8783472df1de3adc70df9b0f04f05000000006b483045022100ea006269fdf8b7308107e9469e575af4eeb2dbf1bcb273416ba6da92106ad56302206affb99984a40334c7d8b991c285a5f89e47ff62879e69b28fafecf7bd70b00f012102a97bf098a7cfc5c81a113b76922ef24abfa27d6e9991db724f9090a8426c9d53ffffffff024084fe00000000001976a914a1c03c1932f6afd5eab9163f9140151cae17df3388ac40420f00000000001976a9148c9648cab53a1fb8861daff0f2378c7b9e81a3ab88ac00000000"),
      Transaction.read("0100000001cec6dd9f7ddc640f7bb54daf5623040532b8783472df1de3adc70df9b0f04f05010000006b483045022100d6fb138dca5e6cce925a4bcc322d02ab194f68a0c2794bb1a555dc1ff8c2465f02205a4977af8f398b013da33e61a35f83578c3a9cccea3328b6c982ff4dc8092c7e01210224fc92517bc13b1e9f609054afc2539f2f121f4c1e45fb46fac21364c42440c6ffffffff01400d0300000000001976a9146a3e65bf746bcd7af3493e19451451a8a4da331588ac00000000"),
      Transaction.read("01000000016d1f1a7f8c1307139ef78080ba8442852c6766d3fbb826d2ac0e6fb2f72dd8dc000000008b483045022100bdd23d0f98a4173a64fa432b8bf4ac41261a671f2c6c690d57ac839866d78bb202207bddb87ca95c9cef45de30a75144e5513571aa7938635b9e051b1c20f01088a60141044aec194c55c97f4519535f50f5539c6915045ecb79a36281dee6db55ffe1ad2e55f4a1c0e0950d3511e8f205b45cafa348a4a2ab2359246cb3c93f6532c4e8f5ffffffff0140548900000000001976a914c622640075eaeda95a5ac26fa05a0b894a3def8c88ac00000000")
    )
    val keys = List(
      SignData(previousTx(0).txOut(1).publicKeyScript, Base58Check.decode("cW6bSKtH3oMPA18cXSMR8ASHztrmbwmCyqvvN8x3Tc7WG6TyrJDg")._2),
      SignData(previousTx(1).txOut(0).publicKeyScript, Base58Check.decode("93Ag8t83NW9WmPbhqLCSUNckARpbpgWtp4EWGidtj6h6pVQgGN4")._2),
      SignData(previousTx(2).txOut(0).publicKeyScript, Base58Check.decode("921vnTeSQCN7GMHdiHyaoZ1JSugTtzvg8rqyXH9HmFtBgrNDxCT")._2)
    )

    val dest1 = "n2Jrcf7cJH7wMJdhKZGVi2jaSnV2BwYE9m" //priv: 926iWgQDq5dN84BJ4q2fu4wjSSaVWFxwanE8EegzMh3vGCUBJ94
    val dest2 = "mk6kmMF5EEXksBkZxi7FniwwRgWuZuwDpo" //priv: 91r7coHBdzfgfm2p3ToJ3Bu6kcqL3BvSo5m4ENzMZzsimRKH8aq
    // 0.03 and 0.07 BTC in satoshi, meaning the fee will be (0.01+0.002+0.09)-(0.03+0.07) = 0.002
    val amount1 = 3000000 satoshi
    val amount2 = 7000000 satoshi

    // create a tx with empty input signature scripts
    val tx = Transaction(
      version = 1L,
      txIn = List(
        TxIn(OutPoint(previousTx(0), 1), Array.empty[Byte], 0xffffffffL),
        TxIn(OutPoint(previousTx(1), 0), Array.empty[Byte], 0xffffffffL),
        TxIn(OutPoint(previousTx(2), 0), Array.empty[Byte], 0xffffffffL)
      ),
      txOut = List(TxOut(
        amount = amount1,
        publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(dest1)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil),
        TxOut(
          amount = amount2,
          publicKeyScript = OP_DUP :: OP_HASH160 :: OP_PUSHDATA(Base58Check.decode(dest2)._2) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil)),
      lockTime = 0L
    )

    val signedTx = Transaction.sign(tx, keys)

    //this works because signature is not randomized
    toHexString(Transaction.write(signedTx)) should equal("0100000003864d5e5ec82c9e6f4ac52b8fa47b77f8616bbc26fcf668432c097c5add169584010000006a47304402203be0cff1faacadce3b02d615a8ac15532f9a90bd30e109eaa3e01bfa3a97d90b0220355f3bc382e35b9cae24e5d674f200b289bb948675ce1b5c931029ccb23ae836012102fd18c2a069488288ae93c2157dff3fd657a39426e8753512a5547f046b4a2cbbffffffffd587b10688e6d56225dd4dc488b74229a353e4613cbe1deadaef52b56616baa9000000008b483045022100ab98145e8526b32e821beeaed41a98da68c3c75ee13c477ee0e3d66a626217e902204d015af2e7dba834bbe421dd0b1353a1060dafee58c284dd763e07639858f9340141043ca81d9fe7996372eb21b2588af07c7fbdb6d4fc1da13aaf953c520ba1da4f87d53dfcba3525369fdb248e60233fdf6df0a8183a6dd5699c9a6f5c537367c627ffffffff94a162b4aab080a09fa982a5d7f586045ba2a4c653c98ff47b952d43c25b45fd000000008a47304402200e0c0223d169282a48731b58ff0673c00205deb3f3f4f28d99b50730ada1571402202fa9f051762d8e0199791ea135df1f393578c1eea530bec00fa16f6bba7e3aa3014104626f9b06c44bcfd5d2f6bdeab456591287e2d2b2e299815edf0c9fd0f23c21364ed5dbe97c9c6e2be40fff40c31f8561a9dee015146fe59ecf68b8a377292c72ffffffff02c0c62d00000000001976a914e410e8bc694e8a39c32a273eb1d71930f63648fe88acc0cf6a00000000001976a914324505870d6f21dca7d2f90642cd9603553f6fa688ac00000000")

    // the id of this tx on testnet is e8570dd062de8e354b18f6308ff739a51f25db75563c4ee2bc5849281263528f

    // redeem tx
    Transaction.correctlySpends(signedTx, previousTx, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
  }
}
