package fr.acinq.bitcoin

import java.io.{ByteArrayInputStream, InputStream, OutputStream}
import java.nio.ByteOrder
import Protocol._
import fr.acinq.bitcoin.Crypto.PublicKey
import fr.acinq.bitcoin.DeterministicWallet.KeyPath

object PSBT {

  case class MapEntry(key: BinaryData, value: BinaryData)

  case class PartiallySignedInput(
    witnessOutput:Option[TxOut],
    nonWitnessOutput: Option[Transaction],
    partialSigs: Map[PublicKey, BinaryData],
    sighashType: Option[Int],
    inputIndex: Option[Int]
  )

  case class PartiallySignedTransaction(
    tx: Transaction,
    redeemScripts: Seq[Seq[ScriptElt]],
    witnessScripts: Seq[Seq[ScriptElt]],
    inputs: Seq[PartiallySignedInput],
    bip32Data: Option[(PublicKey, KeyPath)]
  )

  final val PSBD_MAGIC = 0x70736274
  final val HEADER_SEPARATOR = 0xff
  final val SEPARATOR = 0x00

  object GlobalTypes extends Enumeration {
    val TransactionType = Value(0x00, "Transaction type")
    val RedeemScript = Value(0x01, "Redeem script type")
    val WitnessScript = Value(0x02, "Witness script type")
    val Bip32Data = Value(0x03, "BIP32 data type")
    val PSBTInputsNumber = Value(0x04, "Number of inputs of the PSBT type")
  }

  object InputTypes extends Enumeration {
    val NonWitnessUTXO = Value(0x00, "Non witness UTXO type")
    val WitnessUTXO = Value(0x01, "Witness UTXO type")
    val PartialSignature = Value(0x02, "Partial signature type")
    val SighashType = Value(0x03, "Sighash type")
    val InputIndex = Value(0x04, "Input index type")
  }

  //Reads a list of key values, terminated by 0x00
  private def readKeyValueMap(input: InputStream): Seq[MapEntry] = {
    val keyLength = varint(input)
    if(keyLength == SEPARATOR) {
      return Nil
    }

    val key = BinaryData(new Array[Byte](keyLength.toInt))
    input.read(key)

    val dataLength = varint(input)
    val data = BinaryData(new Array[Byte](dataLength.toInt))
    input.read(data)

    readKeyValueMap(input) :+ MapEntry(key, data)
  }

  private def keyType[T <: Enumeration](key: BinaryData, enumType: T): enumType.Value = {
    if(key.length == 0) {
      throw new IllegalArgumentException("zero length PSBT key encountered")
    }

    enumType(key.head)
  }

  def read(input: String): PartiallySignedTransaction = {
    read(new ByteArrayInputStream(BinaryData(input)))
  }

  //TODO add unknowns
  def read(input: InputStream): PartiallySignedTransaction = {
    import GlobalTypes._
    import InputTypes._

    var useInIndex = false

    val psbtMagic = uint32(input, ByteOrder.BIG_ENDIAN)
    val separator = uint8(input)
    assert(psbtMagic == PSBD_MAGIC && separator == HEADER_SEPARATOR, s"PSBT header not valid '$psbtMagic|$separator'")

    //Read exactly one map for globals
    val globalMap = readKeyValueMap(input)

    var inputMaps:Seq[Seq[MapEntry]] = Seq.empty
    while(input.available() > 0){
      inputMaps = inputMaps :+ readKeyValueMap(input)
    }

    val tx = globalMap.find(el => keyType(el.key, GlobalTypes) == TransactionType) match {
      case Some(entry) => Transaction.read(entry.value)
      case None        => throw new IllegalArgumentException("PSBT requires one key-value entry for type Transaction")
    }

    val redeemScripts = globalMap.filter(el => keyType(el.key, GlobalTypes) == RedeemScript).map { redeemScriptsEntry =>
      assert(redeemScriptsEntry.key.size == 21, s"Redeem script key has invalid size: ${redeemScriptsEntry.key.size}")
      val scriptHash = redeemScriptsEntry.key.drop(1)
      val redeemScript = Script.parse(redeemScriptsEntry.value)
      assert(BinaryData(scriptHash) == Crypto.hash160(redeemScriptsEntry.value), "Provided hash160 does not match the redeemscript's hash160")
      redeemScript
    }

    val witnessScripts = globalMap.filter(el => keyType(el.key, GlobalTypes) == WitnessScript).map { witnessScriptsEntry =>
      assert(witnessScriptsEntry.key.size == 33, s"Witness script key has invalid size: ${witnessScriptsEntry.key.size}")
      val scriptHash = witnessScriptsEntry.key.drop(1)
      val witnessScript = Script.parse(witnessScriptsEntry.value)
      assert(BinaryData(scriptHash) == Crypto.hash256(witnessScriptsEntry.value), "Provided sha256 does not match the witnessscript's sha256")
      witnessScript
    }

    val keyPaths = globalMap.find(el => keyType(el.key, GlobalTypes) == Bip32Data).map { mapEntry =>
      val pubKey = PublicKey(mapEntry.key.drop(1))
      assert(Crypto.isPubKeyValid(pubKey.data), "Invalid pubKey parsed")
      val derivationPaths = mapEntry.value.sliding(4).map(bytes => uint32(BinaryData(bytes), ByteOrder.LITTLE_ENDIAN))
      (pubKey, KeyPath(derivationPaths.toSeq))
    }

    val numberOfInputs = globalMap.find(el => keyType(el.key, GlobalTypes) == PSBTInputsNumber) match {
      case Some(psbtInputsNumberEntry) => varint(psbtInputsNumberEntry.value)
      case None                        => 0
    }

    val psbis = inputMaps.zipWithIndex.map { case (inputMap, index) =>
      val partiallySignedInput = PartiallySignedInput(
        inputMap.find(el => keyType(el.key, InputTypes) == WitnessUTXO).map { witnessUtxoEntry =>
          TxOut.read(witnessUtxoEntry.value)
        },
        inputMap.find(el => keyType(el.key, InputTypes) == NonWitnessUTXO).map { nonWitnessUtxoEntry =>
          Transaction.read(nonWitnessUtxoEntry.value)
        },
        inputMap.filter(el => keyType(el.key, InputTypes) == PartialSignature).map { partSigEntry =>
          PublicKey(partSigEntry.key.drop(1)) -> partSigEntry.value
        }.toMap,
        inputMap.find(el => keyType(el.key, InputTypes) == SighashType).map { sigHashEntry =>
          uint32(sigHashEntry.value, ByteOrder.LITTLE_ENDIAN).toInt
        },
        inputMap.find(el => keyType(el.key, InputTypes) == InputIndex).map { inputIndexEntry =>
          varint(inputIndexEntry.value.data.toArray).toInt
        }
      )

      if(useInIndex && partiallySignedInput.inputIndex.isEmpty){
        throw new IllegalArgumentException("Input indexes being used but an input was provided without an index")
      }

      if(partiallySignedInput.inputIndex.isDefined){
        useInIndex = true
      }

      partiallySignedInput.nonWitnessOutput.map { prevTx =>
        assert(tx.txIn(partiallySignedInput.inputIndex.getOrElse(index)).outPoint.hash == prevTx.hash, "Provided non witness utxo does not match the required utxo for input")
      }

      partiallySignedInput.inputIndex match {
        case None => partiallySignedInput.copy(inputIndex = Some(index))
        case _    => partiallySignedInput
      }
    }

    //FIXME this check should keep in account already finalized (signed) inputs
    assert(tx.txIn.filterNot(txIn => !txIn.hasSigScript || !txIn.hasWitness).size == psbis.size, s"The number of inputs provided (${psbis.size}) does not match the inputs in the transaction (${tx.txIn.size})")

    PartiallySignedTransaction(tx, redeemScripts, witnessScripts, psbis, keyPaths)
  }

  def write(psbt: PartiallySignedTransaction, out: OutputStream)= ???

}
