package fr.acinq.bitcoin

import java.io.{ByteArrayInputStream, InputStream, OutputStream}
import java.nio.ByteOrder
import Protocol._
import fr.acinq.bitcoin.Crypto.PublicKey
import fr.acinq.bitcoin.Crypto._
import fr.acinq.bitcoin.DeterministicWallet.KeyPath
import scala.annotation.tailrec

object PSBT {

  type Script = Seq[ScriptElt]

  case class MapEntry(key: BinaryData, value: BinaryData)

  case class PartiallySignedInput(
    nonWitnessOutput: Option[Transaction] = None,
    witnessOutput:Option[TxOut] = None,
    redeemScript: Option[Script] = None,
    witnessScript: Option[Script] = None,
    finalScriptSig: Option[Script] = None,
    finalScriptWitness: Option[ScriptWitness] = None,
    bip32Data: Map[PublicKey, KeyPath] = Map.empty,
    partialSigs: Map[PublicKey, BinaryData] = Map.empty,
    sighashType: Option[Int] = None,
    unknowns: Seq[MapEntry] = Seq.empty
  )

  case class PartiallySignedOutput(
    redeemScript: Option[Script],
    witnessScript: Option[Script],
    bip32Data: Map[PublicKey, KeyPath],
    unknowns: Seq[MapEntry] = Seq.empty
  )

  case class PartiallySignedTransaction(
    tx: Transaction,
    inputs: Seq[PartiallySignedInput],
    outputs: Seq[PartiallySignedOutput],
    unknowns: Seq[MapEntry] = Seq.empty
  )

  final val PSBD_MAGIC = 0x70736274
  final val HEADER_SEPARATOR = 0xff
  final val SEPARATOR = 0x00

  object GlobalTypes extends Enumeration {
    val TransactionType = Value(0x00, "Transaction")
  }

  object InputTypes extends Enumeration {
    val NonWitnessUTXO = Value(0x00, "Non witness UTXO")
    val WitnessUTXO = Value(0x01, "Witness UTXO")
    val PartialSignature = Value(0x02, "Partial signature")
    val SighashType = Value(0x03, "Sighash")
    val RedeemScript = Value(0x04, "Redeem script")
    val WitnessScript = Value(0x05, "Witness script")
    val Bip32Data = Value(0x06, "Keypath for HD keys")
    val FinalScriptSig = Value(0x07, "Finalized scriptSig")
    val FinalScriptWitness = Value(0x08, "Finalized witness script")
  }

  object OutputTypes extends Enumeration {
    val RedeemScript = Value(0x00, "Redeem script")
    val WitnessScript = Value(0x01, "Witness script")
    val Bip32Data = Value(0x02, "Keypath for HD keys")
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

  @tailrec
  private def readMaps(counter: Int = 0, input: InputStream, acc: Seq[Seq[MapEntry]] = Seq.empty): Seq[Seq[MapEntry]] = {
    if(counter > 0) {
      readMaps(counter - 1, input, acc :+ readKeyValueMap(input))
    } else {
      acc
    }
  }

  private def assertNoDuplicates(psbtMap: Seq[MapEntry]) = {
    val setSmallerThanList = psbtMap.map(_.key).distinct.size < psbtMap.size
    assert(psbtMap.size < 2 || !setSmallerThanList, "Duplicate keys not allowed") //TODO add the key
  }

  private def isKeyUnknown[T <: Enumeration](key: BinaryData, enumType: T): Boolean = {
    !enumType.values.map(_.id).contains(key.head) // { 0x00, 0x01, 0x02, 0x03, 0x04 }
  }

  private def mapEntryToKeyPaths(entry: MapEntry):(PublicKey, KeyPath) = {
    val pubKey = PublicKey(entry.key.drop(1))
    assert(isPubKeyValid(pubKey.data), "Invalid pubKey parsed")
    val derivationPaths = entry.value.sliding(4).map(uint32(_, ByteOrder.LITTLE_ENDIAN))
    (pubKey, KeyPath(derivationPaths.toSeq))
  }

  private def mapEntryToScript(entry: MapEntry): Script = Script.parse(entry.value)

  def read64(input: String): PartiallySignedTransaction = {
    read(new ByteArrayInputStream(fromBase64String(input)))
  }

  def read(input: InputStream): PartiallySignedTransaction = {
    import GlobalTypes._
    import InputTypes._

    val psbtMagic = uint32(input, ByteOrder.BIG_ENDIAN)
    val separator = uint8(input)
    assert(psbtMagic == PSBD_MAGIC && separator == HEADER_SEPARATOR, s"PSBT header not valid '$psbtMagic|$separator'")

    //Read exactly one map for globals
    val globalMap = readKeyValueMap(input)

    val tx = globalMap.find(_.key.head == TransactionType.id) match {
      case Some(entry) => Transaction.read(entry.value)
      case None        => throw new IllegalArgumentException("PSBT requires one key-value entry for type Transaction")
    }

    tx.txIn.foreach { in =>
      assert(!in.hasSigScript && !in.hasWitness, s"Non empty input(${TxIn.write(in).toString}) found in the transaction")
    }

    val globalUnknowns = globalMap.filter(el => isKeyUnknown(el.key, GlobalTypes))

    //Read as many maps as the inputs/outpus found on the unsigned transaction
    val inputMaps = readMaps(tx.txIn.size, input)
    val outputMaps = readMaps(tx.txOut.size, input)

    //Assert there are no repeated keys within each maps's scope
    assertNoDuplicates(globalMap)
    inputMaps.foreach(assertNoDuplicates)
    outputMaps.foreach(assertNoDuplicates)

    val psbis = inputMaps.map { inputMap =>

      val redeemOut = inputMap.find(_.key.head == NonWitnessUTXO.id).map { nonWitnessUtxoEntry =>
        Transaction.read(nonWitnessUtxoEntry.value)
      }

      val witOut =  inputMap.find(_.key.head == WitnessUTXO.id).map { witnessUtxoEntry =>
        TxOut.read(witnessUtxoEntry.value)
      }

      val redeemScript = inputMap.find(_.key.head == RedeemScript.id).map(mapEntryToScript)
      val witScript = inputMap.find(_.key.head == WitnessScript.id).map(mapEntryToScript)
      val finRedeemScript = inputMap.find(_.key.head == FinalScriptSig.id).map(mapEntryToScript)
      val finWitScript = inputMap.find(_.key.head == FinalScriptWitness.id).map { finScriptWitnessEntry =>
        ScriptWitness.read(finScriptWitnessEntry.value)
      }

      val hdKeyPath = inputMap.filter(_.key.head == Bip32Data.id).map(mapEntryToKeyPaths).toMap

      val sigHash = inputMap.find(_.key.head == SighashType.id).map { sigHashEntry =>
        uint32(sigHashEntry.value, ByteOrder.LITTLE_ENDIAN).toInt
      }

      val partialSig = inputMap.filter(_.key.head == PartialSignature.id).map { partSigEntry =>
        PublicKey(partSigEntry.key.drop(1)) -> partSigEntry.value
      }.toMap

      val unknowns = inputMap.filter(el => isKeyUnknown(el.key, InputTypes))

      PartiallySignedInput(redeemOut, witOut, redeemScript, witScript, finRedeemScript, finWitScript, hdKeyPath, partialSig, sigHash, unknowns)
    }

    val psbtOuts = outputMaps.map { outputMap =>

      val redeemScript = outputMap.find(_.key.head == OutputTypes.RedeemScript.id).map(mapEntryToScript)
      val witScript = outputMap.find(_.key.head == OutputTypes.WitnessScript.id).map(mapEntryToScript)
      val hdKeyPaths = outputMap.filter(_.key.head == OutputTypes.Bip32Data.id).map(mapEntryToKeyPaths).toMap

      PartiallySignedOutput(redeemScript, witScript, hdKeyPaths)
    }

    PartiallySignedTransaction(tx, psbis, psbtOuts, globalUnknowns)
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

//    val txEntry = MapEntry(Seq(TransactionType.id.toByte), Transaction.write(psbt.tx))
//
//    val redeemScriptEntries = psbt.redeemScripts.map { redeemScript =>
//      MapEntry(Seq(RedeemScript.id.byteValue) ++ hash160(Script.write(redeemScript)), Script.write(redeemScript))
//    }
//
//    val witnessScriptEntries = psbt.witnessScripts.map { witScript =>
//      MapEntry(Seq(WitnessScript.id.byteValue) ++ sha256(Script.write(witScript)), Script.write(witScript))
//    }
//
//    val bip32Data = psbt.bip32Data.map { data =>
//      MapEntry(Seq(Bip32Data.id.byteValue) ++ data._1.data, data._2.map(writeUInt32).flatten)
//    }
//
//    val numberOfInputs = psbt.numberOfInputs match {
//      case i if i > 0 => Some(MapEntry(Seq(PSBTInputsNumber.id.byteValue), writeVarint(psbt.inputs.size)))
//      case _          => None
//    }
//
//    writeKeyValue(txEntry, out)
//    redeemScriptEntries.foreach(writeKeyValue(_, out))
//    witnessScriptEntries.foreach(writeKeyValue(_, out))
//    bip32Data.foreach(writeKeyValue(_, out))
//    numberOfInputs.map(writeKeyValue(_, out))
//    psbt.unknowns.map(writeKeyValue(_, out))
//
//    writeUInt8(SEPARATOR, out)
//
//    psbt.inputs.foreach { input =>
//
//      val nonWitOut = input.nonWitnessOutput.map(tx => MapEntry(Seq(NonWitnessUTXO.id.byteValue), Transaction.write(tx)))
//      val witnessOut = input.witnessOutput.map(out => MapEntry(Seq(WitnessUTXO.id.byteValue), TxOut.write(out)))
//      val partialSig = input.partialSigs.map { case (pk, sig) => MapEntry(Seq(PartialSignature.id.byteValue) ++ pk.data, sig) }
//      val sigHashType = input.sighashType.map( sigHash => MapEntry(Seq(SighashType.id.byteValue), writeUInt32(sigHash, ByteOrder.LITTLE_ENDIAN)))
//      val inputIndex = input.inputIndex.map( idx => MapEntry(Seq(InputIndex.id.byteValue), writeVarint(idx)) )
//
//      nonWitOut.map(writeKeyValue(_, out))
//      witnessOut.map(writeKeyValue(_, out))
//      partialSig.map(writeKeyValue(_, out))
//      sigHashType.map(writeKeyValue(_, out))
//      inputIndex.map(writeKeyValue(_, out))
//      input.unknowns.map(writeKeyValue(_, out))
//
//      writeUInt8(SEPARATOR, out)
//
//    }

  }

}
