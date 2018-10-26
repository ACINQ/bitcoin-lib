package fr.acinq.bitcoin

import java.math.BigInteger
import java.util

import org.scalatest.FlatSpec

class Base58Spec extends FlatSpec {

  import fr.acinq.bitcoin.Base58._

  "Base58" should "encode byte arrays" in {
    assert(encode("Hello World".getBytes("UTF-8")) === "JxF12TrwUP45BMd")
    assert(encode(BigInteger.valueOf(3471844090L).toByteArray) === "16Ho7Hs")
    assert(encode(new Array[Byte](1)) === "1")
    assert(encode(new Array[Byte](7)) === "1111111")
    assert(encode(new Array[Byte](0)) === "")
  }

  it should "decode strings" in {
    assert(util.Arrays.equals(decode("JxF12TrwUP45BMd"), "Hello World".getBytes("UTF-8")))
    assert(util.Arrays.equals(decode(""), new Array[Byte](0)))
    assert(util.Arrays.equals(decode("1"), new Array[Byte](1)))
    assert(util.Arrays.equals(decode("1111111"), new Array[Byte](7)))
    decode("93VYUMzRG9DdbRP72uQXjaWibbQwygnvaCu9DumcqDjGybD864T")
    intercept[NoSuchElementException] {
      decode("This isn't valid base58")
    }
  }
}
