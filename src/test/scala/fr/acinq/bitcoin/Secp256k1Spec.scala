package fr.acinq.bitcoin

import fr.acinq.bitcoin.Crypto.PrivateKey
import fr.acinq.secp256k1.Secp256k1
import org.scalatest.FunSuite
import scodec.bits.ByteVector

import scala.util.{Random, Try}

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
  val nativeSecp256k1 = try {
    Some(Secp256k1.get())
  }
  catch {
    case t: Throwable =>
      None
  }
  
  test("deterministic signatures") {
    assume(nativeSecp256k1.isDefined)
    val priv = new Array[Byte](32)
    val data = new Array[Byte](32)
    for (i <- 0 until 1000) {
      Random.nextBytes(priv)
      Random.nextBytes(data)
      val sig1: ByteVector = Crypto.sign(ByteVector.view(data), PrivateKey(ByteVector.view(priv)))
      val sig2: ByteVector = ByteVector.view(nativeSecp256k1.get.sign(data, priv))
      assert(sig1 == sig2)
    }
  }
  test("ecdh") {
    assume(nativeSecp256k1.isDefined)
    val priv1 = new Array[Byte](32)
    val priv2 = new Array[Byte](32)
    for (i <- 0 until 1000) {
      Random.nextBytes(priv1)
      Random.nextBytes(priv2)
      val secret1: ByteVector = Crypto.ecdh(PrivateKey(ByteVector.view(priv1)), PrivateKey(ByteVector.view(priv2)).publicKey)
      val secret2: ByteVector = ByteVector.view(nativeSecp256k1.get.ecdh(priv1, Secp256k1.get().pubkeyCreate(priv2)))
      assert(secret1 == secret2)
    }
  }
}
