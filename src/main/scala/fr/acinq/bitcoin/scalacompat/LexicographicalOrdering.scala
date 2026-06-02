package fr.acinq.bitcoin.scalacompat

import scodec.bits.ByteVector

import scala.annotation.tailrec

/**
 * Lexicographical Ordering of Transaction Inputs and Outputs
 * see https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
 */
object LexicographicalOrdering {
  def isLessThan(a: ByteVector, b: ByteVector): Boolean = fr.acinq.bitcoin.LexicographicalOrdering.isLessThan(a.toArrayUnsafe, b.toArrayUnsafe)

  def isLessThan(a: OutPoint, b: OutPoint): Boolean = {
    if (a.txid == b.txid) a.index < b.index
    else isLessThan(a.txid.value, b.txid.value)
  }

  def isLessThan(a: TxIn, b: TxIn): Boolean = isLessThan(a.outPoint, b.outPoint)

  def isLessThan(a: TxOut, b: TxOut): Boolean = {
    if (a.amount == b.amount) isLessThan(a.publicKeyScript, b.publicKeyScript)
    else a.amount.compare(b.amount) < 0
  }

  /**
   * @param tx input transaction
   * @return the input tx with inputs and outputs sorted in lexicographical order
   */
  def sort(tx: Transaction): Transaction = tx.copy(txIn = tx.txIn.sortWith(isLessThan), txOut = tx.txOut.sortWith(isLessThan))
}
