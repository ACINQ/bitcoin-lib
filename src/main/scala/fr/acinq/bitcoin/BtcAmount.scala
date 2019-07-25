package fr.acinq.bitcoin

sealed trait BtcAmount {
  def toMilliSatoshi: MilliSatoshi
  def toSatoshi: Satoshi = millisatoshi2satoshi(toMilliSatoshi)
  def toMilliBtc: MilliBtc = satoshi2millibtc(toSatoshi)
  def toBtc: Btc = millibtc2btc(toMilliBtc)
}

case class Satoshi(amount: Long) extends BtcAmount {
  // @formatter:off
    def toLong = amount
    def +(other: Satoshi) = Satoshi(amount + other.amount)
    def -(other: Satoshi) = Satoshi(amount - other.amount)
    def *(m: Long) = Satoshi(amount * m)
    def /(d: Long) = Satoshi(amount / d)

    def compare(other: BtcAmount): Int = this.toMilliSatoshi.compare(other.toMilliSatoshi)

    def <= (that: MilliSatoshi): Boolean = compare(that) <= 0
    def <= (that: Satoshi): Boolean = compare(that) <= 0
    def <= (that: MilliBtc): Boolean = compare(that) <= 0
    def <= (that: Btc): Boolean = compare(that) <= 0

    def >= (that: MilliSatoshi): Boolean = compare(that) >= 0
    def >= (that: Satoshi): Boolean = compare(that) >= 0
    def >= (that: MilliBtc): Boolean = compare(that) >= 0
    def >= (that: Btc): Boolean = compare(that) >= 0

    def <  (that: MilliSatoshi): Boolean = compare(that) <  0
    def <  (that: Satoshi): Boolean = compare(that) <  0
    def <  (that: MilliBtc): Boolean = compare(that) <  0
    def <  (that: Btc): Boolean = compare(that) <  0

    def >  (that: MilliSatoshi): Boolean = compare(that) > 0
    def >  (that: Satoshi): Boolean = compare(that) > 0
    def >  (that: MilliBtc): Boolean = compare(that) > 0
    def >  (that: Btc): Boolean = compare(that) > 0

    def unary_-() = Satoshi(-amount)
    def toMilliSatoshi: MilliSatoshi = satoshi2millisatoshi(this)
    // @formatter:on
}

case class MilliBtc(amount: BigDecimal) extends BtcAmount {
  // @formatter:off
    def +(other: MilliBtc) = MilliBtc(amount + other.amount)
    def -(other: MilliBtc) = MilliBtc(amount - other.amount)
    def *(m: Long) = MilliBtc(amount * m)
    def /(d: Long) = MilliBtc(amount / d)

    def compare(other: BtcAmount): Int = this.toMilliSatoshi.compare(other.toMilliSatoshi)

    def <= (that: MilliSatoshi): Boolean = compare(that) <= 0
    def <= (that: Satoshi): Boolean = compare(that) <= 0
    def <= (that: MilliBtc): Boolean = compare(that) <= 0
    def <= (that: Btc): Boolean = compare(that) <= 0

    def >= (that: MilliSatoshi): Boolean = compare(that) >= 0
    def >= (that: Satoshi): Boolean = compare(that) >= 0
    def >= (that: MilliBtc): Boolean = compare(that) >= 0
    def >= (that: Btc): Boolean = compare(that) >= 0

    def <  (that: MilliSatoshi): Boolean = compare(that) <  0
    def <  (that: Satoshi): Boolean = compare(that) <  0
    def <  (that: MilliBtc): Boolean = compare(that) <  0
    def <  (that: Btc): Boolean = compare(that) <  0

    def >  (that: MilliSatoshi): Boolean = compare(that) > 0
    def >  (that: Satoshi): Boolean = compare(that) > 0
    def >  (that: MilliBtc): Boolean = compare(that) > 0
    def >  (that: Btc): Boolean = compare(that) > 0

    def unary_-() = MilliBtc(-amount)
    def toMilliSatoshi: MilliSatoshi = millibtc2millisatoshi(this)
    // @formatter:on
}

case class Btc(amount: BigDecimal) extends BtcAmount {
  require(amount.abs <= 21e6, "amount must not be greater than 21 millions")

  // @formatter:off
    def +(other: Btc) = Btc(amount + other.amount)
    def -(other: Btc) = Btc(amount - other.amount)
    def *(m: Long) = Btc(amount * m)
    def /(d: Long) = Btc(amount / d)

    def compare(other: BtcAmount): Int = this.toMilliSatoshi.compare(other.toMilliSatoshi)

    def <= (that: MilliSatoshi): Boolean = compare(that) <= 0
    def <= (that: Satoshi): Boolean = compare(that) <= 0
    def <= (that: MilliBtc): Boolean = compare(that) <= 0
    def <= (that: Btc): Boolean = compare(that) <= 0

    def >= (that: MilliSatoshi): Boolean = compare(that) >= 0
    def >= (that: Satoshi): Boolean = compare(that) >= 0
    def >= (that: MilliBtc): Boolean = compare(that) >= 0
    def >= (that: Btc): Boolean = compare(that) >= 0

    def <  (that: MilliSatoshi): Boolean = compare(that) <  0
    def <  (that: Satoshi): Boolean = compare(that) <  0
    def <  (that: MilliBtc): Boolean = compare(that) <  0
    def <  (that: Btc): Boolean = compare(that) <  0

    def >  (that: MilliSatoshi): Boolean = compare(that) > 0
    def >  (that: Satoshi): Boolean = compare(that) > 0
    def >  (that: MilliBtc): Boolean = compare(that) > 0
    def >  (that: Btc): Boolean = compare(that) > 0

    def unary_-() = Btc(-amount)
    def toMilliSatoshi: MilliSatoshi = btc2millisatoshi(this)
    // @formatter:on
}

case class MilliSatoshi(amount: Long) extends BtcAmount {
  // @formatter:off
    def toLong = amount
    def +(other: MilliSatoshi) = MilliSatoshi(amount + other.amount)
    def -(other: MilliSatoshi) = MilliSatoshi(amount - other.amount)
    def *(m: Long) = MilliSatoshi(amount * m)
    def /(d: Long) = MilliSatoshi(amount / d)

    def compare(other: BtcAmount): Int = if (amount == other.toMilliSatoshi.amount) 0 else if (amount < other.toMilliSatoshi.amount) -1 else 1

    def <= (that: MilliSatoshi): Boolean = compare(that) <= 0
    def <= (that: Satoshi): Boolean = compare(that) <= 0
    def <= (that: MilliBtc): Boolean = compare(that) <= 0
    def <= (that: Btc): Boolean = compare(that) <= 0

    def >= (that: MilliSatoshi): Boolean = compare(that) >= 0
    def >= (that: Satoshi): Boolean = compare(that) >= 0
    def >= (that: MilliBtc): Boolean = compare(that) >= 0
    def >= (that: Btc): Boolean = compare(that) >= 0

    def <  (that: MilliSatoshi): Boolean = compare(that) <  0
    def <  (that: Satoshi): Boolean = compare(that) <  0
    def <  (that: MilliBtc): Boolean = compare(that) <  0
    def <  (that: Btc): Boolean = compare(that) <  0

    def >  (that: MilliSatoshi): Boolean = compare(that) > 0
    def >  (that: Satoshi): Boolean = compare(that) > 0
    def >  (that: MilliBtc): Boolean = compare(that) > 0
    def >  (that: Btc): Boolean = compare(that) > 0

    def unary_-() = MilliSatoshi(-amount)
    def toMilliSatoshi: MilliSatoshi = this
    // @formatter:on
}

