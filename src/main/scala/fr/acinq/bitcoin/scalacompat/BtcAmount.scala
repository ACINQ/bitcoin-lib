package fr.acinq.bitcoin.scalacompat

sealed trait BtcAmount

case class Satoshi(private val underlying: Long) extends BtcAmount with Ordered[Satoshi] {
  // @formatter:off
  def +(other: Satoshi): Satoshi = Satoshi(underlying + other.underlying)
  def -(other: Satoshi): Satoshi = Satoshi(underlying - other.underlying)
  def unary_- : Satoshi = Satoshi(-underlying)
  def *(m: Long): Satoshi = Satoshi(underlying * m)
  def *(m: Double): Satoshi = Satoshi((underlying * m).toLong)
  def /(d: Long): Satoshi = Satoshi(underlying / d)
  def compare(other: Satoshi): Int = underlying.compare(other.underlying)
  def max(other: BtcAmount): Satoshi = other match {
    case other: Satoshi => if (underlying > other.underlying) this else other
    case other: MilliBtc => if (underlying > other.toSatoshi.underlying) this else other.toSatoshi
    case other: Btc => if (underlying > other.toSatoshi.underlying) this else other.toSatoshi
  }
  def min(other: BtcAmount): Satoshi = other match {
    case other: Satoshi => if (underlying < other.underlying) this else other
    case other: MilliBtc => if (underlying < other.toSatoshi.underlying) this else other.toSatoshi
    case other: Btc => if (underlying < other.toSatoshi.underlying) this else other.toSatoshi
  }
  def toBtc: Btc = Btc(BigDecimal(underlying) / BtcAmount.Coin)
  def toMilliBtc: MilliBtc = toBtc.toMilliBtc
  def toLong: Long = underlying
  override def toString = s"$underlying sat"
  // @formatter:on
}

case class MilliBtc(private val underlying: BigDecimal) extends BtcAmount with Ordered[MilliBtc] {
  // @formatter:off
  def +(other: MilliBtc): MilliBtc = MilliBtc(underlying + other.underlying)
  def -(other: MilliBtc): MilliBtc = MilliBtc(underlying - other.underlying)
  def unary_- : MilliBtc = MilliBtc(-underlying)
  def *(m: Long): MilliBtc = MilliBtc(underlying * m)
  def *(m: Double): MilliBtc = MilliBtc(underlying * m)
  def /(d: Long): MilliBtc = MilliBtc(underlying / d)
  def compare(other: MilliBtc): Int = underlying.compare(other.underlying)
  def max(other: BtcAmount): MilliBtc = other match {
    case other: Satoshi => if (underlying > other.toMilliBtc.underlying) this else other.toMilliBtc
    case other: MilliBtc => if (underlying > other.underlying) this else other
    case other: Btc => if (underlying > other.toMilliBtc.underlying) this else other.toMilliBtc
  }
  def min(other: BtcAmount): MilliBtc = other match {
    case other: Satoshi => if (underlying < other.toMilliBtc.underlying) this else other.toMilliBtc
    case other: MilliBtc => if (underlying < other.underlying) this else other
    case other: Btc => if (underlying < other.toMilliBtc.underlying) this else other.toMilliBtc
  }
  def toBtc: Btc = Btc(underlying / 1000)
  def toSatoshi: Satoshi = toBtc.toSatoshi
  def toBigDecimal: BigDecimal = underlying
  def toDouble: Double = underlying.toDouble
  def toLong: Long = underlying.toLong
  override def toString = s"$underlying mBTC"
  // @formatter:on
}

case class Btc(private val underlying: BigDecimal) extends BtcAmount with Ordered[Btc] {
  require(underlying.abs <= 21e6, "amount must not be greater than 21 millions")

  // @formatter:off
  def +(other: Btc): Btc = Btc(underlying + other.underlying)
  def -(other: Btc): Btc = Btc(underlying - other.underlying)
  def unary_- : Btc = Btc(-underlying)
  def *(m: Long): Btc = Btc(underlying * m)
  def *(m: Double): Btc = Btc(underlying * m)
  def /(d: Long): Btc = Btc(underlying / d)
  def compare(other: Btc): Int = underlying.compare(other.underlying)
  def max(other: BtcAmount): Btc = other match {
    case other: Satoshi => if (underlying > other.toBtc.underlying) this else other.toBtc
    case other: MilliBtc => if (underlying > other.toBtc.underlying) this else other.toBtc
    case other: Btc => if (underlying > other.underlying) this else other
  }
  def min(other: BtcAmount): Btc = other match {
    case other: Satoshi => if (underlying < other.toBtc.underlying) this else other.toBtc
    case other: MilliBtc => if (underlying < other.toBtc.underlying) this else other.toBtc
    case other: Btc => if (underlying < other.underlying) this else other
  }
  def toMilliBtc: MilliBtc = MilliBtc(underlying * 1000)
  def toSatoshi: Satoshi = Satoshi((underlying * BtcAmount.Coin).toLong)
  def toBigDecimal: BigDecimal = underlying
  def toDouble: Double = underlying.toDouble
  def toLong: Long = underlying.toLong
  override def toString = s"$underlying BTC"
  // @formatter:on
}

object BtcAmount {
  val Coin = 100000000L
  val Cent = 1000000L
  val MaxMoney: Double = 21e6 * Coin
}