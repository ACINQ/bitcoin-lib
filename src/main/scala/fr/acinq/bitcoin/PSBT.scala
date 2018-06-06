package fr.acinq.bitcoin

import java.io.{InputStream, OutputStream}
import java.nio.ByteOrder

import Protocol._
import fr.acinq.bitcoin.Crypto.PublicKey
import fr.acinq.bitcoin.DeterministicWallet.KeyPath

object PSBT {

  case class PartiallySignedInput(
    witnessOutput:Option[Seq[ScriptElt]],
    nonWitnessOutput: Option[Seq[ScriptElt]],
    partialSigs: Map[PublicKey, BinaryData],
    sighashType:Int,
    inputIndex: Long
  )

  case class PartiallySignedTransaction(
    tx: Transaction,
    redeemScripts: Seq[Seq[ScriptElt]],
    witnessScripts: Seq[Seq[ScriptElt]],
    inputs: Seq[PartiallySignedInput],
    keyPaths: Seq[KeyPath]
  )

  final val PSBD_MAGIC = 0x70736274
  final val HEADER_SEPARATOR = 0xff
  final val SEPARATOR = 0x00

  object GlobalTypes extends Enumeration {
    val transaction = Value(0x00, "Transaction type")
    val redeemScript = Value(0x01, "Redeem script type")
    val witnessScript = Value(0x02, "Witness script type")
    val bip32Data = Value(0x03, "BIP32 data type")
    val PSBTInputsNumber = Value(0x04, "Number of inputs of the PSBT type")
  }

  object InputTypes extends Enumeration {
    val nonWitnessUTXO = Value(0x00, "Non witness UTXO type")
    val witnessUTXO = Value(0x01, "Witness UTXO type")
    val partialSignature = Value(0x02, "Partial signature type")
    val sighashType = Value(0x03, "Sighash type")
    val inputIndex = Value(0x04, "Input index type")
  }

  private def readKeyValueMap(input: InputStream): Seq[(BinaryData, BinaryData)] = {
    if(input.available() == 0) {
      return Nil
    }

    val keyLength = varint(input)
    if(keyLength == SEPARATOR) {
      return Nil
    }

    val key = BinaryData(new Array[Byte](keyLength.toInt))
    input.read(key)

    val dataLength = varint(input)
    val data = BinaryData(new Array[Byte](dataLength.toInt))
    input.read(data)

    Seq( (key, data) ) ++ readKeyValueMap(input)

  }

  def read(input: InputStream): PartiallySignedTransaction = {
    val psbtMagic = uint32(input, ByteOrder.BIG_ENDIAN)
    val separator = uint8(input)
    assert(psbtMagic == PSBD_MAGIC && separator == HEADER_SEPARATOR, s"PSBT header not valid '$psbtMagic $separator'")
    val globalMap = readKeyValueMap(input)
    val inputsMap = readKeyValueMap(input)

    val tx = globalMap.find( entry => entry._1 == GlobalTypes.transaction.id) match {
      case Some(entry) => Transaction.read(entry._2)
      case None        => throw new IllegalArgumentException("PSBT requires one key-value entry for type Transaction")
    }



    throw new RuntimeException("Not yet implemented")
  }

  def write(psbt: PartiallySignedTransaction, out: OutputStream)= ???

}
