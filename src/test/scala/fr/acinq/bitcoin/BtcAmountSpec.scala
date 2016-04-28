package fr.acinq.bitcoin

import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class BtcAmountSpec extends FunSuite {

  test("btc/satoshi conversions") {
    val x = 12.34567 btc
    val y: MilliBtc = x
    val z: Satoshi = x
    val z1: Satoshi = y
    assert(z === z1)
    assert(y.amount === BigDecimal(12345.67))
    assert(z.amount === 1234567000L)
    val x1: Btc = z1
    assert(x1 === x)
    val x2: MilliBtc = z1
    assert(x2 === y)
  }

  test("conversions overflow") {
    intercept[IllegalArgumentException] {
      val toomany = 22e6 btc
    }
  }
}
