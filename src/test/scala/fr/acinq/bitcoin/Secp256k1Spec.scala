package fr.acinq.bitcoin

import fr.acinq.bitcoin.Crypto.PrivateKey
import org.bitcoin.{NativeSecp256k1, Secp256k1Context}
import org.scalatest.FunSuite
import scodec.bits.ByteVector

import scala.util.Random

/**
  * run this test with -Djava.library.path=$PATH_LIBSECP256K1_DIR where $PATH_LIBSECP256K1_DIR is a directory that
  * contains libsecp256k1.so. For example:
  * mvn test  -DargLine="-Djava.library.path=$PATH_LIBSECP256K1_DIR"
  * To create libsecp256k1.so:
  * clone libsecp256k1
  * $./autogen.sh && ./configure --enable-experimental --enable-module_ecdh --enable-jni && make clean && make && make check
  * libsecp256k1.so should be in the .libs/ directory
  */
class Secp256k1Spec extends FunSuite {
  test("deterministic signatures") {
    assume(Secp256k1Context.isEnabled)
    val priv = new Array[Byte](32)
    val data = new Array[Byte](32)
    for (i <- 0 until 1000) {
      Random.nextBytes(priv)
      Random.nextBytes(data)
      val sig1: ByteVector = Crypto.sign(ByteVector.view(data), PrivateKey(ByteVector.view(priv)))
      val sig2: ByteVector = ByteVector.view(NativeSecp256k1.signCompact(data, priv))
      assert(sig1 == sig2)
    }
  }
  test("ecdh") {
    assume(Secp256k1Context.isEnabled)
    val priv1 = new Array[Byte](32)
    val priv2 = new Array[Byte](32)
    for (i <- 0 until 1000) {
      Random.nextBytes(priv1)
      Random.nextBytes(priv2)
      val secret1: ByteVector = Crypto.ecdh(PrivateKey(ByteVector.view(priv1)), PrivateKey(ByteVector.view(priv2)).publicKey)
      val secret2: ByteVector = ByteVector.view(NativeSecp256k1.createECDHSecret(priv1, NativeSecp256k1.computePubkey(priv2)))
      assert(secret1 == secret2)
    }
  }
}
