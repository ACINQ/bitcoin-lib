package fr.acinq.bitcoin

sealed trait BtcAmount

case class Satoshi(amount: Long) extends BtcAmount {
  // @formatter:off
    def toLong = amount
    def +(other: Satoshi) = Satoshi(amount + other.amount)
    def -(other: Satoshi) = Satoshi(amount - other.amount)
    def *(m: Long) = Satoshi(amount * m)
    def /(d: Long) = Satoshi(amount / d)
    def compare(other: Satoshi): Int = if (amount == other.toLong) 0 else if (amount < other.amount) -1 else 1
    def <= (that: Satoshi): Boolean = compare(that) <= 0
    def >= (that: Satoshi): Boolean = compare(that) >= 0
    def <  (that: Satoshi): Boolean = compare(that) <  0
    def >  (that: Satoshi): Boolean = compare(that) > 0
    // @formatter:on
}

case class MilliBtc(amount: BigDecimal) extends BtcAmount

case class Btc(amount: BigDecimal) extends BtcAmount {
  require(amount.abs <= 21e6, "amount must not be greater than 21 millions")
}

case class MilliSatoshi(amount: Long) extends BtcAmount

