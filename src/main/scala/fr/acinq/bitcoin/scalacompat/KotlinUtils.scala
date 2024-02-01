package fr.acinq.bitcoin.scalacompat

import fr.acinq.bitcoin
import fr.acinq.bitcoin.scalacompat.Crypto.{PrivateKey, PublicKey}
import scodec.bits.ByteVector

import java.io.{InputStream, OutputStream}
import scala.jdk.CollectionConverters.{ListHasAsScala, SeqHasAsJava}

object KotlinUtils {
  implicit def kmp2scala(input: bitcoin.ByteVector32): ByteVector32 = ByteVector32(ByteVector(input.toByteArray))

  implicit def scala2kmp(input: ByteVector32): bitcoin.ByteVector32 = new bitcoin.ByteVector32(input.toArray)

  implicit def kmp2scala(input: bitcoin.ByteVector64): ByteVector64 = ByteVector64(ByteVector(input.toByteArray))

  implicit def scala2kmp(input: ByteVector64): bitcoin.ByteVector64 = new bitcoin.ByteVector64(input.toArray)

  implicit def kmp2scala(input: bitcoin.ByteVector): ByteVector = ByteVector(input.toByteArray)

  implicit def scala2kmp(input: ByteVector): bitcoin.ByteVector = new bitcoin.ByteVector(input.toArray)

  implicit def kmp2scala(input: bitcoin.TxId): TxId = TxId(input.value)

  implicit def scala2kmp(input: TxId): bitcoin.TxId = new bitcoin.TxId(input.value)

  implicit def kmp2scala(input: bitcoin.TxHash): TxHash = TxHash(input.value)

  implicit def scala2kmp(input: TxHash): bitcoin.TxHash = new bitcoin.TxHash(input.value)

  implicit def kmp2scala(input: bitcoin.BlockId): BlockId = BlockId(input.value)

  implicit def scala2kmp(input: BlockId): bitcoin.BlockId = new bitcoin.BlockId(input.value)

  implicit def kmp2scala(input: bitcoin.BlockHash): BlockHash = BlockHash(input.value)

  implicit def scala2kmp(input: BlockHash): bitcoin.BlockHash = new bitcoin.BlockHash(input.value)

  implicit def kmp2scala(input: bitcoin.OutPoint): OutPoint = OutPoint(input.hash, input.index)

  implicit def scala2kmp(input: OutPoint): bitcoin.OutPoint = new bitcoin.OutPoint(input.hash, input.index)

  implicit def kmp2scala(input: bitcoin.ScriptWitness): ScriptWitness = ScriptWitness(input.stack.asScala.toList.map(kmp2scala))

  implicit def scala2kmp(input: ScriptWitness): bitcoin.ScriptWitness = new bitcoin.ScriptWitness(input.stack.map(scala2kmp).asJava)

  implicit def kmp2scala(input: bitcoin.TxIn): TxIn = TxIn(input.outPoint, input.signatureScript, input.sequence, input.witness)

  implicit def scala2kmp(input: Satoshi): bitcoin.Satoshi = new bitcoin.Satoshi(input.toLong)

  implicit def kmp2scala(input: bitcoin.Satoshi): Satoshi = Satoshi(input.toLong)

  implicit def scala2kmp(input: TxIn): bitcoin.TxIn = new bitcoin.TxIn(scala2kmp(input.outPoint), input.signatureScript, input.sequence, scala2kmp(input.witness))

  implicit def kmp2scala(input: bitcoin.TxOut): TxOut = TxOut(input.amount, input.publicKeyScript)

  implicit def scala2kmp(input: TxOut): bitcoin.TxOut = new bitcoin.TxOut(input.amount, input.publicKeyScript)

  implicit def kmp2scala(input: bitcoin.Transaction): Transaction = Transaction(input.version, input.txIn.asScala.toList.map(kmp2scala), input.txOut.asScala.toList.map(kmp2scala), input.lockTime)

  implicit def scala2kmp(input: Transaction): bitcoin.Transaction = new bitcoin.Transaction(input.version, input.txIn.map(scala2kmp).asJava, input.txOut.map(scala2kmp).asJava, input.lockTime)

  implicit def kmp2scala(input: bitcoin.PrivateKey): PrivateKey = PrivateKey(input)

  implicit def scala2kmp(input: PrivateKey): bitcoin.PrivateKey = new bitcoin.PrivateKey(input.value)

  implicit def kmp2scala(input: bitcoin.PublicKey): PublicKey = PublicKey(input)

  implicit def scala2kmp(input: PublicKey): bitcoin.PublicKey = new bitcoin.PublicKey(input.value)

  implicit def kmp2scala(input: bitcoin.DeterministicWallet.ExtendedPrivateKey): DeterministicWallet.ExtendedPrivateKey = DeterministicWallet.ExtendedPrivateKey(input)

  implicit def scala2kmp(input: DeterministicWallet.ExtendedPrivateKey): bitcoin.DeterministicWallet.ExtendedPrivateKey = input.priv

  implicit def kmp2scala(input: bitcoin.DeterministicWallet.ExtendedPublicKey): DeterministicWallet.ExtendedPublicKey = DeterministicWallet.ExtendedPublicKey(input)

  implicit def scala2kmp(input: DeterministicWallet.ExtendedPublicKey): bitcoin.DeterministicWallet.ExtendedPublicKey = input.pub

  implicit def kmp2scala(input: bitcoin.KeyPath): DeterministicWallet.KeyPath = DeterministicWallet.KeyPath(input)

  implicit def scala2kmp(input: DeterministicWallet.KeyPath): bitcoin.KeyPath = input.keyPath

  case class InputStreamWrapper(is: InputStream) extends bitcoin.io.Input {
    // NB: on the JVM we will use a ByteArrayInputStream, which guarantees that the result will be correct.
    override def getAvailableBytes: Int = is.available()

    override def read(): Int = is.read()

    override def read(bytes: Array[Byte], i: Int, i1: Int): Int = is.read(bytes, i, i1)
  }

  case class OutputStreamWrapper(os: OutputStream) extends bitcoin.io.Output {
    override def write(bytes: Array[Byte], i: Int, i1: Int): Unit = os.write(bytes, i, i1)

    override def write(i: Int): Unit = os.write(i)
  }

  implicit def eitherkmp2either[L, R](input: fr.acinq.bitcoin.utils.Either[L, R]): Either[L, R] = if (input.isLeft) Left(input.getLeft) else Right(input.getRight)

  implicit def scala2kmp(input: ScriptElt): bitcoin.ScriptElt = input match {
    case OP_PUSHDATA(data, _) => new bitcoin.OP_PUSHDATA(data)
    case _ => scriptEltMapScala2Kmp(input)
  }

  implicit def kmp2scala(input: bitcoin.ScriptElt): ScriptElt = input match {
    case oppushdata: bitcoin.OP_PUSHDATA => OP_PUSHDATA(oppushdata.data, oppushdata.opCode)
    case _ => scriptEltMapKmp2Scala2Map(input)
  }

  private val scriptEltMapScala2Kmp: Map[ScriptElt, bitcoin.ScriptElt] = Map(
    OP_0 -> bitcoin.OP_0.INSTANCE,
    OP_1NEGATE -> bitcoin.OP_1NEGATE.INSTANCE,
    OP_RESERVED -> bitcoin.OP_RESERVED.INSTANCE,
    OP_1 -> bitcoin.OP_1.INSTANCE,
    OP_2 -> bitcoin.OP_2.INSTANCE,
    OP_3 -> bitcoin.OP_3.INSTANCE,
    OP_4 -> bitcoin.OP_4.INSTANCE,
    OP_5 -> bitcoin.OP_5.INSTANCE,
    OP_6 -> bitcoin.OP_6.INSTANCE,
    OP_7 -> bitcoin.OP_7.INSTANCE,
    OP_8 -> bitcoin.OP_8.INSTANCE,
    OP_9 -> bitcoin.OP_9.INSTANCE,
    OP_10 -> bitcoin.OP_10.INSTANCE,
    OP_11 -> bitcoin.OP_11.INSTANCE,
    OP_12 -> bitcoin.OP_12.INSTANCE,
    OP_13 -> bitcoin.OP_13.INSTANCE,
    OP_14 -> bitcoin.OP_14.INSTANCE,
    OP_15 -> bitcoin.OP_15.INSTANCE,
    OP_16 -> bitcoin.OP_16.INSTANCE,
    OP_NOP -> bitcoin.OP_NOP.INSTANCE,
    OP_VER -> bitcoin.OP_VER.INSTANCE,
    OP_IF -> bitcoin.OP_IF.INSTANCE,
    OP_NOTIF -> bitcoin.OP_NOTIF.INSTANCE,
    OP_VERIF -> bitcoin.OP_VERIF.INSTANCE,
    OP_VERNOTIF -> bitcoin.OP_VERNOTIF.INSTANCE,
    OP_ELSE -> bitcoin.OP_ELSE.INSTANCE,
    OP_ENDIF -> bitcoin.OP_ENDIF.INSTANCE,
    OP_VERIFY -> bitcoin.OP_VERIFY.INSTANCE,
    OP_RETURN -> bitcoin.OP_RETURN.INSTANCE,
    OP_TOALTSTACK -> bitcoin.OP_TOALTSTACK.INSTANCE,
    OP_FROMALTSTACK -> bitcoin.OP_FROMALTSTACK.INSTANCE,
    OP_2DROP -> bitcoin.OP_2DROP.INSTANCE,
    OP_2DUP -> bitcoin.OP_2DUP.INSTANCE,
    OP_3DUP -> bitcoin.OP_3DUP.INSTANCE,
    OP_2OVER -> bitcoin.OP_2OVER.INSTANCE,
    OP_2ROT -> bitcoin.OP_2ROT.INSTANCE,
    OP_2SWAP -> bitcoin.OP_2SWAP.INSTANCE,
    OP_IFDUP -> bitcoin.OP_IFDUP.INSTANCE,
    OP_DEPTH -> bitcoin.OP_DEPTH.INSTANCE,
    OP_DROP -> bitcoin.OP_DROP.INSTANCE,
    OP_DUP -> bitcoin.OP_DUP.INSTANCE,
    OP_NIP -> bitcoin.OP_NIP.INSTANCE,
    OP_OVER -> bitcoin.OP_OVER.INSTANCE,
    OP_PICK -> bitcoin.OP_PICK.INSTANCE,
    OP_ROLL -> bitcoin.OP_ROLL.INSTANCE,
    OP_ROT -> bitcoin.OP_ROT.INSTANCE,
    OP_SWAP -> bitcoin.OP_SWAP.INSTANCE,
    OP_TUCK -> bitcoin.OP_TUCK.INSTANCE,
    OP_CAT -> bitcoin.OP_CAT.INSTANCE,
    OP_SUBSTR -> bitcoin.OP_SUBSTR.INSTANCE,
    OP_LEFT -> bitcoin.OP_LEFT.INSTANCE,
    OP_RIGHT -> bitcoin.OP_RIGHT.INSTANCE,
    OP_SIZE -> bitcoin.OP_SIZE.INSTANCE,
    OP_INVERT -> bitcoin.OP_INVERT.INSTANCE,
    OP_AND -> bitcoin.OP_AND.INSTANCE,
    OP_OR -> bitcoin.OP_OR.INSTANCE,
    OP_XOR -> bitcoin.OP_XOR.INSTANCE,
    OP_EQUAL -> bitcoin.OP_EQUAL.INSTANCE,
    OP_EQUALVERIFY -> bitcoin.OP_EQUALVERIFY.INSTANCE,
    OP_RESERVED1 -> bitcoin.OP_RESERVED1.INSTANCE,
    OP_RESERVED2 -> bitcoin.OP_RESERVED2.INSTANCE,
    OP_1ADD -> bitcoin.OP_1ADD.INSTANCE,
    OP_1SUB -> bitcoin.OP_1SUB.INSTANCE,
    OP_2MUL -> bitcoin.OP_2MUL.INSTANCE,
    OP_2DIV -> bitcoin.OP_2DIV.INSTANCE,
    OP_NEGATE -> bitcoin.OP_NEGATE.INSTANCE,
    OP_ABS -> bitcoin.OP_ABS.INSTANCE,
    OP_NOT -> bitcoin.OP_NOT.INSTANCE,
    OP_0NOTEQUAL -> bitcoin.OP_0NOTEQUAL.INSTANCE,
    OP_ADD -> bitcoin.OP_ADD.INSTANCE,
    OP_SUB -> bitcoin.OP_SUB.INSTANCE,
    OP_MUL -> bitcoin.OP_MUL.INSTANCE,
    OP_DIV -> bitcoin.OP_DIV.INSTANCE,
    OP_MOD -> bitcoin.OP_MOD.INSTANCE,
    OP_LSHIFT -> bitcoin.OP_LSHIFT.INSTANCE,
    OP_RSHIFT -> bitcoin.OP_RSHIFT.INSTANCE,
    OP_BOOLAND -> bitcoin.OP_BOOLAND.INSTANCE,
    OP_BOOLOR -> bitcoin.OP_BOOLOR.INSTANCE,
    OP_NUMEQUAL -> bitcoin.OP_NUMEQUAL.INSTANCE,
    OP_NUMEQUALVERIFY -> bitcoin.OP_NUMEQUALVERIFY.INSTANCE,
    OP_NUMNOTEQUAL -> bitcoin.OP_NUMNOTEQUAL.INSTANCE,
    OP_LESSTHAN -> bitcoin.OP_LESSTHAN.INSTANCE,
    OP_GREATERTHAN -> bitcoin.OP_GREATERTHAN.INSTANCE,
    OP_LESSTHANOREQUAL -> bitcoin.OP_LESSTHANOREQUAL.INSTANCE,
    OP_GREATERTHANOREQUAL -> bitcoin.OP_GREATERTHANOREQUAL.INSTANCE,
    OP_MIN -> bitcoin.OP_MIN.INSTANCE,
    OP_MAX -> bitcoin.OP_MAX.INSTANCE,
    OP_WITHIN -> bitcoin.OP_WITHIN.INSTANCE,
    OP_RIPEMD160 -> bitcoin.OP_RIPEMD160.INSTANCE,
    OP_SHA1 -> bitcoin.OP_SHA1.INSTANCE,
    OP_SHA256 -> bitcoin.OP_SHA256.INSTANCE,
    OP_HASH160 -> bitcoin.OP_HASH160.INSTANCE,
    OP_HASH256 -> bitcoin.OP_HASH256.INSTANCE,
    OP_CODESEPARATOR -> bitcoin.OP_CODESEPARATOR.INSTANCE,
    OP_CHECKSIG -> bitcoin.OP_CHECKSIG.INSTANCE,
    OP_CHECKSIGADD -> bitcoin.OP_CHECKSIGADD.INSTANCE,
    OP_CHECKSIGVERIFY -> bitcoin.OP_CHECKSIGVERIFY.INSTANCE,
    OP_CHECKMULTISIG -> bitcoin.OP_CHECKMULTISIG.INSTANCE,
    OP_CHECKMULTISIGVERIFY -> bitcoin.OP_CHECKMULTISIGVERIFY.INSTANCE,
    OP_NOP1 -> bitcoin.OP_NOP1.INSTANCE,
    OP_CHECKLOCKTIMEVERIFY -> bitcoin.OP_CHECKLOCKTIMEVERIFY.INSTANCE,
    OP_CHECKSEQUENCEVERIFY -> bitcoin.OP_CHECKSEQUENCEVERIFY.INSTANCE,
    OP_NOP4 -> bitcoin.OP_NOP4.INSTANCE,
    OP_NOP5 -> bitcoin.OP_NOP5.INSTANCE,
    OP_NOP6 -> bitcoin.OP_NOP6.INSTANCE,
    OP_NOP7 -> bitcoin.OP_NOP7.INSTANCE,
    OP_NOP8 -> bitcoin.OP_NOP8.INSTANCE,
    OP_NOP9 -> bitcoin.OP_NOP9.INSTANCE,
    OP_NOP10 -> bitcoin.OP_NOP10.INSTANCE,
    OP_INVALIDOPCODE -> bitcoin.OP_INVALIDOPCODE.INSTANCE)

  private val scriptEltMapKmp2Scala2Map: Map[bitcoin.ScriptElt, ScriptElt] = scriptEltMapScala2Kmp.map { case (k, v) => v -> k }
}

