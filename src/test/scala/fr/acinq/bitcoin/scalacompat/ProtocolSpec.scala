package fr.acinq.bitcoin.scalacompat

import java.math.BigInteger
import java.net.InetAddress
import com.google.common.io.ByteStreams
import fr.acinq.bitcoin.{Base58, Base58Check}
import org.scalatest.FlatSpec
import scodec.bits._

class ProtocolSpec extends FlatSpec {
  it should "decode transactions" in {
    // data copied from https://people.xiph.org/~greg/signdemo.txt
    val tx = Transaction.read("01000000010c432f4fb3e871a8bda638350b3d5c698cf431db8d6031b53e3fb5159e59d4a90000000000ffffffff0100f2052a010000001976a9143744841e13b90b4aca16fe793a7f88da3a23cc7188ac00000000")
    val script = Script.parse(tx.txOut(0).publicKeyScript)
    val publicKeyHash = Script.publicKeyHash(script)
    assert(Base58Check.encode(Base58.Prefix.PubkeyAddressTestnet, publicKeyHash.toArray) === "mkZBYBiq6DNoQEKakpMJegyDbw2YiNQnHT")
  }
}
