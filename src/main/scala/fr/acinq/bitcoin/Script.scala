package fr.acinq.bitcoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, InputStream, OutputStream}

object Script {

  import fr.acinq.bitcoin.ScriptElt._

  /**
   * parse a script from a input stream of binary data
   * @param input input stream
   * @param stack initial command stack
   * @return an updated command stack
   */
  def parse(input: InputStream, stack: collection.immutable.Vector[ScriptElt] = Vector.empty[ScriptElt]): List[ScriptElt] = {
    input.read() match {
      case -1 => stack.toList
      case opCode if opCode > 0 && opCode < 0x4c => parse(input, stack :+ OP_PUSHDATA(bytes(input, opCode)))
      case 0x4c => parse(input, stack :+ OP_PUSHDATA(bytes(input, uint8(input))))
      case 0x4d => parse(input, stack :+ OP_PUSHDATA(bytes(input, uint16(input))))
      case 0x4e => parse(input, stack :+ OP_PUSHDATA(bytes(input, uint32(input))))
      case opCode if opCode == 0 || opCode > 0x4e => parse(input, stack :+ code2elt(opCode))
    }
  }

  def parse(blob: Array[Byte]): List[ScriptElt] = parse(new ByteArrayInputStream(blob))

  def write(script: List[ScriptElt], out: OutputStream): Unit = script match {
    case Nil => ()
    case OP_PUSHDATA(data) :: tail if data.length < 0x4c => out.write(data.length); out.write(data); write(tail, out)
    case OP_PUSHDATA(data) :: tail if data.length < 0xff => writeUInt8(0x4c, out); writeUInt8(data.length, out); out.write(data); write(tail, out)
    case OP_PUSHDATA(data) :: tail if data.length < 0xffff => writeUInt8(0x4d, out); writeUInt16(data.length, out); out.write(data); write(tail, out)
    case OP_PUSHDATA(data) :: tail if data.length < 0xffffffff => writeUInt8(0x4e, out); writeUInt32(data.length, out); out.write(data); write(tail, out)
    case head :: tail => out.write(elt2code(head)); write(tail, out)
  }

  def write(script: List[ScriptElt]): Array[Byte] = {
    val out = new ByteArrayOutputStream()
    write(script, out)
    out.toByteArray
  }

  def isNop(op: ScriptElt) = op match {
    case OP_NOP | OP_NOP1 | OP_NOP2 | OP_NOP3 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => true
    case _ => false
  }

  def isSimpleValue(op: ScriptElt) = op match {
    case OP_1 | OP_2 | OP_3 | OP_4 | OP_5 | OP_6 | OP_7 | OP_8 | OP_9 | OP_10 | OP_11 | OP_12 | OP_13 | OP_15 | OP_16 => true
    case _ => false
  }

  def simpleValue(op: ScriptElt) : Byte = {
    require(isSimpleValue(op))
    (elt2code(op) - 0x50).toByte
  }

  /**
   * execution context of a tx script
   * @param tx current transaction
   * @param inputIndex 0-based index of the input that is being processed
   * @param previousOutputScript public key script of the output we are trying to claim
   */
  case class Context(tx: Transaction, inputIndex: Int, previousOutputScript: Array[Byte]) {
    require(inputIndex >= 0 && inputIndex < tx.txIn.length, "invalid input index")
  }

  /**
   * Bitcoin script runner
   * @param context script execution context
   */
  class Runner(context: Context) {
    def run(script: Array[Byte]): List[Array[Byte]] = run(parse(script))
    def run(script: Array[Byte], stack: List[Array[Byte]]): List[Array[Byte]] = run(parse(script), stack, List())
    def run(script: List[ScriptElt]): List[Array[Byte]] = run(script, List.empty[Array[Byte]], List())

    /**
     * run a bitcoin script
     * @param script command stack
     * @param stack data stack
     * @return a updated data stack
     */
    def run(script: List[ScriptElt], stack: List[Array[Byte]], conditions: List[Boolean]): List[Array[Byte]] = script match {
      case Nil => stack
      case OP_IF :: tail => stack match {
        case Array(check) :: stacktail if check == 0 => run(tail, stacktail, false :: conditions)
        case head :: stacktail => run(tail, stacktail, true :: conditions)
      }
      case OP_NOTIF :: tail => stack match {
        case Array(check) :: stacktail if check == 0 => run(tail, stacktail, true :: conditions)
        case head :: stacktail => run(tail, stacktail, false :: conditions)
      }
      case OP_ELSE :: tail => run(tail, stack, !conditions.head :: conditions.tail)
      case OP_ENDIF :: tail => run(tail, stack, conditions.tail)
      case head :: tail if conditions.exists(_ == false) => run(tail, stack, conditions)
      case OP_0 :: tail => run(tail, Array.empty[Byte] :: stack, conditions)
      case op :: tail if isSimpleValue(op)=> run(tail, Array(simpleValue(op) : Byte) :: stack, conditions)
      case OP_CHECKSIG :: tail => stack match {
        case pubKey :: sigBytes :: stacktail => {
          val (r, s) = Crypto.decodeSignature(sigBytes)
          val sigHashFlags = sigBytes.last
          val hash = Transaction.hashForSigning(context.tx, context.inputIndex, context.previousOutputScript, sigHashFlags)
          if (!Crypto.verifySignature(hash, (r, s), pubKey)) throw new RuntimeException("OP_CHECKSIG failed")
          run(tail, Array(1: Byte) :: stacktail, conditions)
        }
        case _ => throw new RuntimeException("Cannot perform OP_CHECKSIG on a stack with less than 2 elements")
      }
      case OP_CHECKMULTISIG :: tail => {
        // pop public keys
        val Array(m) = stack.head
        val stack1 = stack.tail
        val pubKeys = stack1.take(m)
        val stack2 = stack1.drop(m)

        // pop signatures
        val Array(n) = stack2.head
        val stack3 = stack2.tail
        val sigs = stack3.take(n)
        val stack4 = stack3.drop(n + 1) // +1 because of a bug in the official client
        var validCount = 0
        for (pubKey <- pubKeys) {
          for (sig <- sigs) {
            val (r, s) = Crypto.decodeSignature(sig)
            val sigHashFlags = sig.last
            val hash = Transaction.hashForSigning(context.tx, context.inputIndex, context.previousOutputScript, sigHashFlags)
            if (Crypto.verifySignature(hash, (r, s), pubKey)) validCount = validCount + 1
          }
        }
        val result = if (validCount >= n) Array(1:Byte) else Array(0:Byte)
        run(tail, result :: stack4, conditions)
      }
      case OP_CODESEPARATOR :: tail => run(tail, stack, conditions)
      case OP_DROP :: tail => run(tail, stack.tail, conditions)
      case OP_DUP :: tail => run(tail, stack.head :: stack, conditions)
      case OP_EQUAL :: tail => stack match {
        case a :: b :: stacktail if !java.util.Arrays.equals(a, b) => run(tail, Array(0:Byte) :: stacktail, conditions)
        case a :: b :: stacktail => run(tail, Array(1:Byte) :: stacktail, conditions)
        case _ => throw new RuntimeException("Cannot perform OP_EQUAL on a stack with less than 2 elements")
      }
      case OP_EQUALVERIFY :: tail => stack match {
        case a :: b :: _ if !java.util.Arrays.equals(a, b) => throw new RuntimeException("OP_EQUALVERIFY failed: elements are different")
        case a :: b :: stacktail => run(tail, stacktail, conditions)
        case _ => throw new RuntimeException("Cannot perform OP_EQUALVERIFY on a stack with less than 2 elements")
      }
      case OP_HASH160 :: tail => run(tail, Crypto.hash160(stack.head) :: stack.tail, conditions)
      case OP_HASH256 :: tail => run(tail, Crypto.hash256(stack.head) :: stack.tail, conditions)
      case op :: tail if isNop(op) => run(tail, stack, conditions)
      case OP_PUSHDATA(data) :: tail => run(tail, data :: stack, conditions)
      case OP_SHA256 :: tail => run(tail, Crypto.sha256(stack.head) :: stack.tail, conditions)
    }
  }

//  def execute(context: Context)(script: List[ScriptElt], stack: List[Array[Byte]] = List.empty[Array[Byte]]): List[Array[Byte]] = script match {
//    case Nil => stack
//    case OP_0 :: tail => execute(context)(tail, Array.empty[Byte] :: stack)
//    case op :: tail if isSimpleValue(op)=> execute(context)(tail, Array(simpleValue(op) : Byte) :: stack)
//    case OP_CHECKSIG :: tail => stack match {
//      case pubKey :: sigBytes :: stacktail => {
//        val (r, s) = Crypto.decodeSignature(sigBytes)
//        val sigHashFlags = sigBytes.last
//        // replace signature script with pubkey script of the output we are trying to redeeem
//        val txin1 = context.tx.txIn(context.inputIndex).copy(signatureScript = context.previousOutputScript)
//        // remove all signature scripts except for the input that we are processing
//        val tx1 = context.tx.copy(txIn = context.tx.txIn.map(_.copy(signatureScript = Array())).updated(context.inputIndex, txin1))
//        val hash = Crypto.hash256(Transaction.write(tx1) ++ writeUInt32(sigHashFlags))
//        if (!Crypto.verifySignature(hash, (r, s), pubKey)) throw new RuntimeException("OP_CHECKSIG failed")
//        execute(context)(tail, Array(1: Byte) :: stacktail)
//      }
//      case _ => throw new RuntimeException("Cannot perform OP_CHECKSIG on a stack with less than 2 elements")
//    }
//    case OP_CHECKMULTISIG :: tail => {
//      // pop public keys
//      val Array(m) = stack.head
//      val stack1 = stack.tail
//      val pubKeys = stack1.take(m)
//      val stack2 = stack1.drop(m)
//
//      // pop signatures
//      val Array(n) = stack2.head
//      val stack3 = stack2.tail
//      val sigs = stack3.take(n)
//      val stack4 = stack3.drop(n + 1) // +1 because of a bug in the official client
//      val serializedTx = {
//        val txin1 = context.tx.txIn(context.inputIndex).copy(signatureScript = context.previousOutputScript)
//        // remove all signature scripts except for the input that we are processing
//        val tx1 = context.tx.copy(txIn = context.tx.txIn.map(_.copy(signatureScript = Array())).updated(context.inputIndex, txin1))
//        Transaction.write(tx1)
//      }
//      var validCount = 0
//      for (pubKey <- pubKeys) {
//        for (sig <- sigs) {
//          val (r, s) = Crypto.decodeSignature(sig)
//          val sigHashFlags = sig.last
//          val hash = Crypto.hash256(serializedTx ++ writeUInt32(sigHashFlags))
//          if (Crypto.verifySignature(hash, (r, s), pubKey)) validCount = validCount + 1
//        }
//      }
//      val result = if (validCount >= n) Array(1:Byte) else Array(0:Byte)
//      execute(context)(tail, result :: stack4)
//    }
//    case OP_CODESEPARATOR :: tail => execute(context)(tail, stack)
//    case OP_DROP :: tail => execute(context)(tail, stack.tail)
//    case OP_DUP :: tail => execute(context)(tail, stack.head :: stack)
//    case OP_EQUAL :: tail => stack match {
//      case a :: b :: stacktail if !java.util.Arrays.equals(a, b) => execute(context)(tail, Array(0:Byte) :: stacktail)
//      case a :: b :: stacktail => execute(context)(tail, Array(1:Byte) :: stacktail)
//      case _ => throw new RuntimeException("Cannot perform OP_EQUAL on a stack with less than 2 elements")
//    }
//    case OP_EQUALVERIFY :: tail => stack match {
//      case a :: b :: _ if !java.util.Arrays.equals(a, b) => throw new RuntimeException("OP_EQUALVERIFY failed: elements are different")
//      case a :: b :: stacktail => execute(context)(tail, stacktail)
//      case _ => throw new RuntimeException("Cannot perform OP_EQUALVERIFY on a stack with less than 2 elements")
//    }
//    case OP_HASH160 :: tail => execute(context)(tail, Crypto.hash160(stack.head) :: stack.tail)
//    case OP_HASH256 :: tail => execute(context)(tail, Crypto.hash256(stack.head) :: stack.tail)
//    case op :: tail if isNop(op) => execute(context)(tail, stack)
//    case OP_PUSHDATA(data) :: tail => execute(context)(tail, data :: stack)
//    case OP_SHA256 :: tail => execute(context)(tail, Crypto.sha256(stack.head) :: stack.tail)
//  }

  /**
   * extract a public key hash from a public key script
   * @param script public key script
   * @return the public key hash wrapped in the script
   */
  def publicKeyHash(script: List[ScriptElt]): Array[Byte] = script match {
    case OP_DUP :: OP_HASH160 :: OP_PUSHDATA(data) :: OP_EQUALVERIFY :: OP_CHECKSIG :: OP_NOP :: Nil => data // non standard pay to pubkey...
    case OP_DUP :: OP_HASH160 :: OP_PUSHDATA(data) :: OP_EQUALVERIFY :: OP_CHECKSIG :: Nil => data // standard pay to pubkey
    case OP_HASH160 :: OP_PUSHDATA(data) :: OP_EQUAL :: Nil if data.size == 20 => data // standard pay to script
  }

  def publicKeyHash(script: Array[Byte]): Array[Byte] = publicKeyHash(parse(script))

  /**
   * extract a public key from a signature script
   * @param script signature script
   * @return the public key wrapped in the script
   */
  def publicKey(script: List[ScriptElt]): Array[Byte] = script match {
    case OP_PUSHDATA(data1) :: OP_PUSHDATA(data2) :: Nil if data1.length > 2 && data2.length > 2 => data2
    case OP_PUSHDATA(data) :: OP_CHECKSIG :: Nil => data
  }

  /**
   * Creates a m-of-n multisig script.
   * @param m is the number of signatures needed
   * @param addresses are the public addresses which associated signatures will be used (m = addresses.size)
   * @return redeem script
   */
  def createMultiSigMofN(m: Int, addresses: List[Array[Byte]]): Array[Byte] = {
    require(m > 0 && m <= 16, s"number of required signatures is $m, should be between 1 and 16")
    require(addresses.size > 0 && addresses.size <= 16, s"number of public keys is ${addresses.size}, should be between 1 and 16")
    require(m <= addresses.size, "The required number of signatures shouldn't be greater than the number of public keys")
    val op_m = ScriptElt.code2elt(m + 0x50) // 1 -> OP_1, 2 -> OP_2, ... 16 -> OP_16
    val op_n = ScriptElt.code2elt(addresses.size + 0x50)
    Script.write(op_m :: addresses.map(OP_PUSHDATA(_)) ::: op_n :: OP_CHECKMULTISIG :: Nil)
  }
}

object CoinbaseScript {
  def parse(blob: Array[Byte]): List[ScriptElt] = List(OP_COINBASE_SCRIPT(blob))
}