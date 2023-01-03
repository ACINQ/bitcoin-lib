package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin
import fr.acinq.bitcoin.scalacompat.Crypto.{PublicKey, XonlyPublicKey}
import scodec.bits.ByteVector

// @formatter:off
abstract class ScriptElt
case object OP_0 extends ScriptElt
case object OP_PUSHDATA1 extends ScriptElt
case object OP_PUSHDATA2 extends ScriptElt
case object OP_PUSHDATA4 extends ScriptElt
case object OP_1NEGATE extends ScriptElt
case object OP_RESERVED extends ScriptElt
case object OP_1 extends ScriptElt
case object OP_2 extends ScriptElt
case object OP_3 extends ScriptElt
case object OP_4 extends ScriptElt
case object OP_5 extends ScriptElt
case object OP_6 extends ScriptElt
case object OP_7 extends ScriptElt
case object OP_8 extends ScriptElt
case object OP_9 extends ScriptElt
case object OP_10 extends ScriptElt
case object OP_11 extends ScriptElt
case object OP_12 extends ScriptElt
case object OP_13 extends ScriptElt
case object OP_14 extends ScriptElt
case object OP_15 extends ScriptElt
case object OP_16 extends ScriptElt
case object OP_NOP extends ScriptElt
case object OP_VER extends ScriptElt
case object OP_IF extends ScriptElt
case object OP_NOTIF extends ScriptElt
case object OP_VERIF extends ScriptElt
case object OP_VERNOTIF extends ScriptElt
case object OP_ELSE extends ScriptElt
case object OP_ENDIF extends ScriptElt
case object OP_VERIFY extends ScriptElt
case object OP_RETURN extends ScriptElt
case object OP_TOALTSTACK extends ScriptElt
case object OP_FROMALTSTACK extends ScriptElt
case object OP_2DROP extends ScriptElt
case object OP_2DUP extends ScriptElt
case object OP_3DUP extends ScriptElt
case object OP_2OVER extends ScriptElt
case object OP_2ROT extends ScriptElt
case object OP_2SWAP extends ScriptElt
case object OP_IFDUP extends ScriptElt
case object OP_DEPTH extends ScriptElt
case object OP_DROP extends ScriptElt
case object OP_DUP extends ScriptElt
case object OP_NIP extends ScriptElt
case object OP_OVER extends ScriptElt
case object OP_PICK extends ScriptElt
case object OP_ROLL extends ScriptElt
case object OP_ROT extends ScriptElt
case object OP_SWAP extends ScriptElt
case object OP_TUCK extends ScriptElt
case object OP_CAT extends ScriptElt
case object OP_SUBSTR extends ScriptElt
case object OP_LEFT extends ScriptElt
case object OP_RIGHT extends ScriptElt
case object OP_SIZE extends ScriptElt
case object OP_INVERT extends ScriptElt
case object OP_AND extends ScriptElt
case object OP_OR extends ScriptElt
case object OP_XOR extends ScriptElt
case object OP_EQUAL extends ScriptElt
case object OP_EQUALVERIFY extends ScriptElt
case object OP_RESERVED1 extends ScriptElt
case object OP_RESERVED2 extends ScriptElt
case object OP_1ADD extends ScriptElt
case object OP_1SUB extends ScriptElt
case object OP_2MUL extends ScriptElt
case object OP_2DIV extends ScriptElt
case object OP_NEGATE extends ScriptElt
case object OP_ABS extends ScriptElt
case object OP_NOT extends ScriptElt
case object OP_0NOTEQUAL extends ScriptElt
case object OP_ADD extends ScriptElt
case object OP_SUB extends ScriptElt
case object OP_MUL extends ScriptElt
case object OP_DIV extends ScriptElt
case object OP_MOD extends ScriptElt
case object OP_LSHIFT extends ScriptElt
case object OP_RSHIFT extends ScriptElt
case object OP_BOOLAND extends ScriptElt
case object OP_BOOLOR extends ScriptElt
case object OP_NUMEQUAL extends ScriptElt
case object OP_NUMEQUALVERIFY extends ScriptElt
case object OP_NUMNOTEQUAL extends ScriptElt
case object OP_LESSTHAN extends ScriptElt
case object OP_GREATERTHAN extends ScriptElt
case object OP_LESSTHANOREQUAL extends ScriptElt
case object OP_GREATERTHANOREQUAL extends ScriptElt
case object OP_MIN extends ScriptElt
case object OP_MAX extends ScriptElt
case object OP_WITHIN extends ScriptElt
case object OP_RIPEMD160 extends ScriptElt
case object OP_SHA1 extends ScriptElt
case object OP_SHA256 extends ScriptElt
case object OP_HASH160 extends ScriptElt
case object OP_HASH256 extends ScriptElt
case object OP_CODESEPARATOR extends ScriptElt
case object OP_CHECKSIG extends ScriptElt
case object OP_CHECKSIGVERIFY extends ScriptElt
case object OP_CHECKSIGADD extends ScriptElt
case object OP_CHECKMULTISIG extends ScriptElt
case object OP_CHECKMULTISIGVERIFY extends ScriptElt
case object OP_NOP1 extends ScriptElt
case object OP_CHECKLOCKTIMEVERIFY extends ScriptElt
case object OP_CHECKSEQUENCEVERIFY extends ScriptElt
case object OP_NOP4 extends ScriptElt
case object OP_NOP5 extends ScriptElt
case object OP_NOP6 extends ScriptElt
case object OP_NOP7 extends ScriptElt
case object OP_NOP8 extends ScriptElt
case object OP_NOP9 extends ScriptElt
case object OP_NOP10 extends ScriptElt
case object OP_SMALLINTEGER extends ScriptElt
case object OP_INVALIDOPCODE extends ScriptElt
object OP_PUSHDATA {
  def apply(data: ByteVector): OP_PUSHDATA = if (data.length < 0x4c) new OP_PUSHDATA(data, data.size.toInt)
  else if (data.length < 0xff) new OP_PUSHDATA(data, 0x4c)
  else if (data.length < 0xffff) new OP_PUSHDATA(data, 0x4d)
  else if (data.length < 0xffffffff) new OP_PUSHDATA(data, 0x4e)
  else throw new IllegalArgumentException(s"data is ${data.length}, too big for OP_PUSHDATA")

  def apply(data: Array[Byte]): OP_PUSHDATA = apply(ByteVector.view(data))

  def apply(pub: PublicKey): OP_PUSHDATA = OP_PUSHDATA(pub.value)

  def apply(pub: XonlyPublicKey): OP_PUSHDATA = OP_PUSHDATA(KotlinUtils.kmp2scala(pub.pub.value))

  def isMinimal(data: ByteVector, code: Int): Boolean = if (data.length == 0) code == ScriptElt.elt2code(OP_0)
  else if (data.length == 1 && data(0) >= 1 && data(0) <= 16) code == ScriptElt.elt2code(OP_1) + (data(0) - 1)
  else if (data.length == 1 && data(0) == 0x81.toByte) code == ScriptElt.elt2code(OP_1NEGATE)
  else if (data.length <= 75) code == data.length
  else if (data.length <= 255) code == ScriptElt.elt2code(OP_PUSHDATA1)
  else if (data.length <= 65535) code == ScriptElt.elt2code(OP_PUSHDATA2)
  else true
}
case class OP_PUSHDATA(data: ByteVector, code: Int) extends ScriptElt {
  override def toString = data.toString
}
case class OP_INVALID(code: Int) extends ScriptElt
// @formatter:off

object ScriptElt {
  // code -> ScriptElt
  def code2elt(code: Int): Option[ScriptElt] = {
    bitcoin.ScriptEltMapping.code2elt.get(code) match {
      case null => None
      case elt => Some(KotlinUtils.kmp2scala(elt))
    }
  }

  // ScriptElt -> code
  def elt2code(elt: ScriptElt): Int = KotlinUtils.scala2kmp(elt).getCode

  def isPush(op: ScriptElt, size: Int): Boolean = {
    op match {
      case OP_PUSHDATA(data, _) => data.length == size
      case _ => false
    }
  }
}
