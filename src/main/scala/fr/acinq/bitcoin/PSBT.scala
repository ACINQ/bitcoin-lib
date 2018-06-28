package fr.acinq.bitcoin

import java.io.{ByteArrayInputStream, InputStream, OutputStream}
import java.nio.ByteOrder
import Protocol._
import fr.acinq.bitcoin.Crypto.PublicKey
import fr.acinq.bitcoin.Crypto._
import fr.acinq.bitcoin.DeterministicWallet.KeyPath
import scala.annotation.tailrec

object PSBT {

  case class MapEntry(key: BinaryData, value: BinaryData)

  case class PartiallySignedInput(
    witnessOutput:Option[TxOut] = None,
    nonWitnessOutput: Option[Transaction] = None,
    partialSigs: Map[PublicKey, BinaryData] = Map.empty,
    sighashType: Option[Int] = None,
    inputIndex: Option[Int] = None,
    unknowns: Seq[MapEntry] = Seq.empty
  )

  case class PartiallySignedTransaction(
    tx: Transaction,
    redeemScripts: Seq[Seq[ScriptElt]],
    witnessScripts: Seq[Seq[ScriptElt]],
    inputs: Seq[PartiallySignedInput],
    bip32Data: Option[(PublicKey, KeyPath)],
    numberOfInputs: Long,
    unknowns: Seq[MapEntry] = Seq.empty
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
  @tailrec
  private def readKeyValueMap(input: InputStream, acc: Seq[MapEntry] = Seq.empty): Seq[MapEntry] = {
    val keyLength = varint(input)
    if(keyLength == SEPARATOR) {
      return acc
    }

    val key = BinaryData(new Array[Byte](keyLength.toInt))
    input.read(key)

    val dataLength = varint(input)
    val data = BinaryData(new Array[Byte](dataLength.toInt))
    input.read(data)

    readKeyValueMap(input, acc :+ MapEntry(key, data))
  }

  private def isGlobalKey(keyType: GlobalTypes.Value) = { entry: MapEntry =>
    !isKeyUnknown(entry.key, GlobalTypes) && GlobalTypes(entry.key.head) == keyType
  }

  private def isInputKey(keyType: InputTypes.Value) = { entry: MapEntry =>
    !isKeyUnknown(entry.key, InputTypes) && InputTypes(entry.key.head) == keyType
  }

  private def isKeyUnknown[T <: Enumeration](key: BinaryData, enumType: T): Boolean = {
    !enumType.values.map(_.id).contains(key.head) // { 0x00, 0x01, 0x02, 0x03, 0x04 }
  }

  def read(input: String): PartiallySignedTransaction = {
    read(new ByteArrayInputStream(BinaryData(input)))
  }

  def read(input: InputStream): PartiallySignedTransaction = {
    import GlobalTypes._
    import InputTypes._

    var useInputIndex = false

    val psbtMagic = uint32(input, ByteOrder.BIG_ENDIAN)
    val separator = uint8(input)
    assert(psbtMagic == PSBD_MAGIC && separator == HEADER_SEPARATOR, s"PSBT header not valid '$psbtMagic|$separator'")

    //Read exactly one map for globals
    val globalMap = readKeyValueMap(input)

    var inputMaps:Seq[Seq[MapEntry]] = Seq.empty
    while(input.available() > 0){
      inputMaps = inputMaps :+ readKeyValueMap(input)
    }

    val tx = globalMap.find(isGlobalKey(TransactionType)) match {
      case Some(entry) => Transaction.read(entry.value)
      case None        => throw new IllegalArgumentException("PSBT requires one key-value entry for type Transaction")
    }

    val redeemScripts = globalMap.filter(isGlobalKey(RedeemScript)).map { redeemScriptsEntry =>
      assert(redeemScriptsEntry.key.size == 21, s"Redeem script key has invalid size: ${redeemScriptsEntry.key.size}")
      val scriptHash = BinaryData(redeemScriptsEntry.key.drop(1))
      val redeemScript = Script.parse(redeemScriptsEntry.value)
      assert(scriptHash == hash160(redeemScriptsEntry.value), "Provided hash160 does not match the redeemscript's hash160")
      redeemScript
    }

    val witnessScripts = globalMap.filter(isGlobalKey(WitnessScript)).map { witnessScriptsEntry =>
      assert(witnessScriptsEntry.key.size == 33, s"Witness script key has invalid size: ${witnessScriptsEntry.key.size}")
      val scriptHash = BinaryData(witnessScriptsEntry.key.drop(1))
      val witnessScript = Script.parse(witnessScriptsEntry.value)
      assert(scriptHash == sha256(witnessScriptsEntry.value), "Provided sha256 does not match the witnessscript's sha256")
      witnessScript
    }

    val keyPaths = globalMap.find(isGlobalKey(Bip32Data)).map { mapEntry =>
      val pubKey = PublicKey(mapEntry.key.drop(1))
      assert(Crypto.isPubKeyValid(pubKey.data), "Invalid pubKey parsed")
      val derivationPaths = mapEntry.value.sliding(4).map(bytes => uint32(BinaryData(bytes), ByteOrder.LITTLE_ENDIAN))
      (pubKey, KeyPath(derivationPaths.toSeq))
    }

    val numberOfInputs = globalMap.find(isGlobalKey(PSBTInputsNumber)) match {
      case Some(psbtInputsNumberEntry) => varint(psbtInputsNumberEntry.value)
      case None                        => 0
    }

    val globalUnknowns = globalMap.filter(el => isKeyUnknown(el.key, GlobalTypes))

    var psbis = inputMaps.zipWithIndex.map { case (inputMap, index) =>
      val partiallySignedInput = PartiallySignedInput(
        inputMap.find(isInputKey(WitnessUTXO)).map { witnessUtxoEntry =>
          TxOut.read(witnessUtxoEntry.value)
        },
        inputMap.find(isInputKey(NonWitnessUTXO)).map { nonWitnessUtxoEntry =>
          Transaction.read(nonWitnessUtxoEntry.value)
        },
        inputMap.filter(isInputKey(PartialSignature)).map { partSigEntry =>
          PublicKey(partSigEntry.key.drop(1)) -> partSigEntry.value
        }.toMap,
        inputMap.find(isInputKey(SighashType)).map { sigHashEntry =>
          uint32(sigHashEntry.value, ByteOrder.LITTLE_ENDIAN).toInt
        },
        inputMap.find(isInputKey(InputIndex)).map { inputIndexEntry =>
          varint(inputIndexEntry.value.data.toArray).toInt
        },
        inputMap.filter(el => isKeyUnknown(el.key, InputTypes))
      )

      //If this is not the first input and it has an input index, make sure all use inputs
      if(!useInputIndex && index != 0 && partiallySignedInput.inputIndex.isDefined){
        throw new IllegalArgumentException("Input indexes being used but an input was provided without an index")
      }

      //If indexes are being used, make sure this input has one
      if(useInputIndex && partiallySignedInput.inputIndex.isEmpty){
        throw new IllegalArgumentException("Input indexes being used but an input was provided without an index")
      }

      if(partiallySignedInput.inputIndex.isDefined){
        useInputIndex = true
      }

      //If the P2PKH UTXO is defined it must match the input's outpoint
      partiallySignedInput.nonWitnessOutput.map { prevTx =>
        assert(tx.txIn(partiallySignedInput.inputIndex.getOrElse(index)).outPoint.hash == prevTx.hash, "Provided non witness utxo does not match the required utxo for input")
      }

      //If no index is provided we use the parsing order
      partiallySignedInput.inputIndex match {
        case None => partiallySignedInput.copy(inputIndex = Some(index))
        case _    => partiallySignedInput
      }
    }

    // Make sure that the number of separators - 1 matches the number of inputs
    // 'psbis' is the result of the parsing, separator-delimited
    if(useInputIndex){
      assert(numberOfInputs == psbis.size,s"Number of inputs specified in 'global' ($numberOfInputs) does not match actual number of inputs in the PSBT (${psbis.size})")
    }

    // If indexes are being used, add a bunch of empty inputs to the input vector so that it matches the number of inputs in the transaction
    if(useInputIndex && tx.txIn.size > psbis.size) {
      val diff = tx.txIn.size - psbis.size
      psbis = psbis ++ ( for(i <- 0 to (diff - 1)) yield PartiallySignedInput(inputIndex = Some(psbis.size + i)) )
    }

    assert(tx.txIn.size == psbis.size, s"The inputs provided (${psbis.size}) does not match the inputs in the transaction (${tx.txIn.size})")

    PartiallySignedTransaction(tx, redeemScripts, witnessScripts, psbis, keyPaths, numberOfInputs, globalUnknowns)
  }

  private def writeKeyValue(entry: MapEntry, out: OutputStream): Unit = {
    val keyLength = entry.key.size
    writeVarint(keyLength, out)
    writeBytes(entry.key, out)

    val valueLength = entry.value.size
    writeVarint(valueLength, out)
    writeBytes(entry.value, out)
  }

  def write(psbt: PartiallySignedTransaction, out: OutputStream): Unit = {
    import GlobalTypes._
    import InputTypes._

    writeUInt32(PSBD_MAGIC, out, ByteOrder.BIG_ENDIAN)
    writeUInt8(HEADER_SEPARATOR, out)

    val txEntry = MapEntry(Seq(TransactionType.id.toByte), Transaction.write(psbt.tx))

    val redeemScriptEntries = psbt.redeemScripts.map { redeemScript =>
      MapEntry(Seq(RedeemScript.id.byteValue) ++ hash160(Script.write(redeemScript)), Script.write(redeemScript))
    }

    val witnessScriptEntries = psbt.witnessScripts.map { witScript =>
      MapEntry(Seq(WitnessScript.id.byteValue) ++ sha256(Script.write(witScript)), Script.write(witScript))
    }

    val bip32Data = psbt.bip32Data.map { data =>
      MapEntry(Seq(Bip32Data.id.byteValue) ++ data._1.data, data._2.map(writeUInt32).flatten)
    }

    val numberOfInputs = psbt.numberOfInputs match {
      case i if i > 0 => Some(MapEntry(Seq(PSBTInputsNumber.id.byteValue), writeVarint(psbt.inputs.size)))
      case _          => None
    }

    writeKeyValue(txEntry, out)
    redeemScriptEntries.foreach(writeKeyValue(_, out))
    witnessScriptEntries.foreach(writeKeyValue(_, out))
    bip32Data.foreach(writeKeyValue(_, out))
    numberOfInputs.map(writeKeyValue(_, out))
    psbt.unknowns.map(writeKeyValue(_, out))

    writeUInt8(SEPARATOR, out)

    psbt.inputs.foreach { input =>

      val nonWitOut = input.nonWitnessOutput.map(tx => MapEntry(Seq(NonWitnessUTXO.id.byteValue), Transaction.write(tx)))
      val witnessOut = input.witnessOutput.map(out => MapEntry(Seq(WitnessUTXO.id.byteValue), TxOut.write(out)))
      val partialSig = input.partialSigs.map { case (pk, sig) => MapEntry(Seq(PartialSignature.id.byteValue) ++ pk.data, sig) }
      val sigHashType = input.sighashType.map( sigHash => MapEntry(Seq(SighashType.id.byteValue), writeUInt32(sigHash, ByteOrder.LITTLE_ENDIAN)))
      val inputIndex = input.inputIndex.map( idx => MapEntry(Seq(InputIndex.id.byteValue), writeVarint(idx)) )

      nonWitOut.map(writeKeyValue(_, out))
      witnessOut.map(writeKeyValue(_, out))
      partialSig.map(writeKeyValue(_, out))
      sigHashType.map(writeKeyValue(_, out))
      inputIndex.map(writeKeyValue(_, out))
      input.unknowns.map(writeKeyValue(_, out))

      writeUInt8(SEPARATOR, out)

    }

  }

}
