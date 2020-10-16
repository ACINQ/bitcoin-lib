package fr.acinq.bitcoin

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, InputStream, OutputStream}
import java.nio.ByteOrder

import fr.acinq.bitcoin.Crypto.PublicKey
import fr.acinq.bitcoin.DeterministicWallet.{ExtendedPublicKey, KeyPath}
import scodec.bits.{ByteVector, HexStringSyntax}

import scala.annotation.tailrec
import scala.util.{Failure, Success, Try}

/**
 * A partially signed bitcoin transaction: see https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki.
 *
 * @param global  global psbt data containing the transaction to be signed.
 * @param inputs  signing data for each input of the transaction to be signed.
 * @param outputs signing data for each output of the transaction to be signed.
 */
case class Psbt(global: Psbt.Global, inputs: Seq[Psbt.PartiallySignedInput], outputs: Seq[Psbt.PartiallySignedOutput]) {
  require(global.tx.txIn.length == inputs.length, "there must be one partially signed input per input of the unsigned tx")
  require(global.tx.txOut.length == outputs.length, "there must be one partially signed output per output of the unsigned tx")
}

/**
 * Partially signed bitcoin transactions: see https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
 */
object Psbt {

  /** Only version 0 is supported for now. */
  val Version: Long = 0

  /**
   * @param prefix               extended public key version bytes.
   * @param masterKeyFingerprint fingerprint of the master key.
   * @param extendedPublicKey    BIP32 extended public key.
   */
  case class ExtendedPublicKeyWithMaster(prefix: Long, masterKeyFingerprint: Long, extendedPublicKey: ExtendedPublicKey)

  /**
   * @param masterKeyFingerprint fingerprint of the master key.
   * @param keyPath              bip 32 derivation path.
   */
  case class KeyPathWithMaster(masterKeyFingerprint: Long, keyPath: KeyPath)

  case class DataEntry(key: ByteVector, value: ByteVector)

  /** A PSBT is a collection of key-value maps. */
  sealed trait DataMap {
    /** Unknown key-value pairs should be ignored but included in the PSBT. */
    def unknown: Seq[DataEntry]
  }

  /**
   * Global data for the PSBT.
   *
   * @param version            psbt version.
   * @param tx                 partially signed transaction.
   * @param extendedPublicKeys (optional) extended public keys used when signing inputs and producing outputs.
   * @param unknown            (optional) unknown global entries.
   */
  case class Global(version: Long, tx: Transaction, extendedPublicKeys: Seq[ExtendedPublicKeyWithMaster], unknown: Seq[DataEntry]) extends DataMap

  /**
   * A partially signed input. A valid PSBT must contain one such input per input of the [[Global.tx]].
   *
   * @param nonWitnessUtxo  non-witness utxo, used when spending non-segwit outputs.
   * @param witnessUtxo     witness utxo, used when spending segwit outputs.
   * @param sighashType     sighash type to be used when producing signature for this output.
   * @param partialSigs     signatures as would be pushed to the stack from a scriptSig or witness.
   * @param derivationPaths derivation paths used for the signatures.
   * @param redeemScript    redeemScript for this input if it has one.
   * @param witnessScript   witnessScript for this input if it has one.
   * @param scriptSig       fully constructed scriptSig with signatures and any other scripts necessary for the input to pass validation.
   * @param scriptWitness   fully constructed scriptWitness with signatures and any other scripts necessary for the input to pass validation.
   * @param unknown         (optional) unknown global entries.
   */
  case class PartiallySignedInput(nonWitnessUtxo: Option[Transaction],
                                  witnessUtxo: Option[TxOut],
                                  sighashType: Option[Int],
                                  partialSigs: Map[PublicKey, ByteVector],
                                  derivationPaths: Map[PublicKey, KeyPathWithMaster],
                                  redeemScript: Option[List[ScriptElt]],
                                  witnessScript: Option[List[ScriptElt]],
                                  scriptSig: Option[List[ScriptElt]],
                                  scriptWitness: Option[ScriptWitness],
                                  unknown: Seq[DataEntry]) extends DataMap

  /**
   * A partially signed output. A valid PSBT must contain one such output per output of the [[Global.tx]].
   *
   * @param redeemScript    redeemScript for this output if it has one.
   * @param witnessScript   witnessScript for this output if it has one.
   * @param derivationPaths derivation paths used to produce the public keys associated to this output.
   * @param unknown         (optional) unknown global entries.
   */
  case class PartiallySignedOutput(redeemScript: Option[List[ScriptElt]],
                                   witnessScript: Option[List[ScriptElt]],
                                   derivationPaths: Map[PublicKey, KeyPathWithMaster],
                                   unknown: Seq[DataEntry]) extends DataMap

  // @formatter:off
  def read(input: InputStream): Try[Psbt] = Codecs.read(input)
  def read(input: Array[Byte]): Try[Psbt] = read(new ByteArrayInputStream(input))
  def read(input: ByteVector): Try[Psbt] = read(input.toArray)
  def fromBase64(input: String): Try[Psbt] = ByteVector.fromBase64(input) match {
    case Some(b) => read(b)
    case None => Failure(new IllegalArgumentException("psbt is not correctly base64-encoded"))
  }
  def write(psbt: Psbt, output: OutputStream): Unit = Codecs.write(psbt, output)
  def write(psbt: Psbt): Array[Byte] = {
    val output = new ByteArrayOutputStream()
    write(psbt, output)
    output.toByteArray
  }
  def toBase64(psbt: Psbt): String = ByteVector(write(psbt)).toBase64
  // @formatter:on

  object Codecs {

    def read(input: InputStream): Try[Psbt] = for {
      _ <- readMagicBytes(input)
      _ <- readSeparator(input)
      global <- readGlobal(input)
      inputs <- readInputs(input, global.tx.txIn.length)
      outputs <- readOutputs(input, global.tx.txOut.length)
    } yield Psbt(global, inputs, outputs)

    private def readMagicBytes(input: InputStream): Try[Boolean] = Try {
      input.readNBytes(4).toList
    } match {
      case Success(0x70 :: 0x73 :: 0x62 :: 0x74 :: Nil) => Success(true)
      case _ => Failure(new IllegalArgumentException("invalid magic bytes: psbt must start with 0x70736274"))
    }

    private def readSeparator(input: InputStream): Try[Boolean] = Try {
      input.read()
    } match {
      case Success(0xff) => Success(true)
      case _ => Failure(new IllegalArgumentException("magic bytes must be followed by the 0xff separator"))
    }

    private def readGlobal(input: InputStream): Try[Global] = readDataMap(input).flatMap(entries => {
      val keyTypes = Set(0x00, 0x01, 0xfb).map(_.toByte)
      val (known, unknown) = entries.partition(entry => entry.key.headOption.exists(keyTypes.contains))
      val version_opt: Try[Long] = known.find(_.key.head == 0xfb).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt version key must contain exactly 1 byte"))
        case DataEntry(_, value) if value.length != 4 => Failure(new IllegalArgumentException("psbt version must be exactly 4 bytes"))
        case DataEntry(_, value) => Protocol.uint32(value, ByteOrder.LITTLE_ENDIAN) match {
          case v if v > Version => Failure(new IllegalArgumentException(s"unsupported psbt version: $v"))
          case v => Success(v)
        }
      }.getOrElse(Success(0))
      val tx_opt: Try[Transaction] = known.find(_.key.head == 0x00).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt tx key must contain exactly 1 byte"))
        case DataEntry(_, value) =>
          val tx = Transaction.read(value.toArray)
          if (tx.txIn.exists(input => input.hasWitness || input.signatureScript.nonEmpty)) {
            Failure(new IllegalArgumentException("psbt tx inputs must have empty scriptSigs and witness"))
          } else {
            Success(tx)
          }
      }.getOrElse(Failure(new IllegalArgumentException("psbt must contain a transaction")))
      val xpubs_opt: Try[Seq[ExtendedPublicKeyWithMaster]] = trySequence(known.filter(_.key.head == 0x01).map {
        case DataEntry(key, _) if key.tail.length != 78 => Failure(new IllegalArgumentException("psbt bip32 xpub must contain exactly 78 bytes"))
        case DataEntry(key, value) =>
          val xpub = new ByteArrayInputStream(key.toArray.tail)
          val prefix = Protocol.uint32(xpub, ByteOrder.BIG_ENDIAN)
          val depth = Protocol.uint8(xpub)
          val parent = Protocol.uint32(xpub, ByteOrder.BIG_ENDIAN)
          val childNumber = Protocol.uint32(xpub, ByteOrder.BIG_ENDIAN)
          val chaincode = ByteVector32(Protocol.bytes(xpub, 32))
          val publicKey = Protocol.bytes(xpub, 33)
          if (value.length != 4 * (depth + 1)) {
            Failure(new IllegalArgumentException("psbt bip32 xpub must contain the master key fingerprint and derivation path"))
          } else {
            val masterKeyFingerprint = Protocol.uint32(value.take(4), ByteOrder.BIG_ENDIAN)
            val derivationPath = KeyPath((0 until depth).map(i => Protocol.uint32(value.slice(4 * (i + 1), 4 * (i + 2)), ByteOrder.LITTLE_ENDIAN)))
            if (derivationPath.lastChildNumber != childNumber) {
              Failure(new IllegalArgumentException("psbt xpub last child number mismatch"))
            } else {
              Success(ExtendedPublicKeyWithMaster(prefix, masterKeyFingerprint, ExtendedPublicKey(publicKey, chaincode, depth, derivationPath, parent)))
            }
          }
      })
      for {
        version <- version_opt
        tx <- tx_opt
        xpubs <- xpubs_opt
      } yield Global(version, tx, xpubs, unknown)
    })

    private def readInputs(input: InputStream, expectedCount: Int): Try[Seq[PartiallySignedInput]] = trySequence((0 until expectedCount).map(_ => readInput(input)))

    private def readInput(input: InputStream): Try[PartiallySignedInput] = readDataMap(input).flatMap(entries => {
      val keyTypes = Set(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08).map(_.toByte)
      val (known, unknown) = entries.partition(entry => entry.key.headOption.exists(keyTypes.contains))
      val nonWitnessUtxo_opt: Try[Option[Transaction]] = known.find(_.key.head == 0x00).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt non-witness utxo key must contain exactly 1 byte"))
        case DataEntry(_, value) => Success(Some(Transaction.read(value.toArray)))
      }.getOrElse(Success(None))
      val witnessUtxo_opt: Try[Option[TxOut]] = known.find(_.key.head == 0x01).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt witness utxo key must contain exactly 1 byte"))
        case DataEntry(_, value) => Success(Some(TxOut.read(value.toArray)))
      }.getOrElse(Success(None))
      val partialSigs_opt: Try[Map[PublicKey, ByteVector]] = trySequence(known.filter(_.key.head == 0x02).map {
        case DataEntry(key, value) => Success(PublicKey(key.tail, checkValid = true), value)
      }).map(_.toMap)
      val sighashType_opt: Try[Option[Int]] = known.find(_.key.head == 0x03).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt sighash type key must contain exactly 1 byte"))
        case DataEntry(_, value) if value.length != 4 => Failure(new IllegalArgumentException("psbt sighash type must contain exactly 4 bytes"))
        case DataEntry(_, value) => Success(Some(Protocol.uint32(value, ByteOrder.LITTLE_ENDIAN).toInt))
      }.getOrElse(Success(None))
      val redeemScript_opt: Try[Option[List[ScriptElt]]] = known.find(_.key.head == 0x04).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt redeem script key must contain exactly 1 byte"))
        case DataEntry(_, value) => Success(Some(Script.parse(value)))
      }.getOrElse(Success(None))
      val witnessScript_opt: Try[Option[List[ScriptElt]]] = known.find(_.key.head == 0x05).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt witness script key must contain exactly 1 byte"))
        case DataEntry(_, value) => Success(Some(Script.parse(value)))
      }.getOrElse(Success(None))
      val derivationPaths_opt: Try[Map[PublicKey, KeyPathWithMaster]] = trySequence(known.filter(_.key.head == 0x06).map {
        case DataEntry(_, value) if value.length < 4 || value.length % 4 != 0 => Failure(new IllegalArgumentException("psbt bip32 derivation must contain master key fingerprint and child indexes"))
        case DataEntry(key, value) =>
          val publicKey = PublicKey(key.tail, checkValid = true)
          val masterKeyFingerprint = Protocol.uint32(value.take(4), ByteOrder.BIG_ENDIAN)
          val childCount = (value.length.toInt / 4) - 1
          val derivationPath = KeyPath((0 until childCount).map(i => Protocol.uint32(value.slice(4 * (i + 1), 4 * (i + 2)), ByteOrder.LITTLE_ENDIAN)))
          Success(publicKey, KeyPathWithMaster(masterKeyFingerprint, derivationPath))
      }).map(_.toMap)
      val scriptSig_opt: Try[Option[List[ScriptElt]]] = known.find(_.key.head == 0x07).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt script sig key must contain exactly 1 byte"))
        case DataEntry(_, value) => Success(Some(Script.parse(value)))
      }.getOrElse(Success(None))
      val scriptWitness_opt: Try[Option[ScriptWitness]] = known.find(_.key.head == 0x08).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt script witness key must contain exactly 1 byte"))
        case DataEntry(_, value) => Success(Some(ScriptWitness.read(value.toArray)))
      }.getOrElse(Success(None))
      for {
        nonWitnessUtxo <- nonWitnessUtxo_opt
        witnessUtxo <- witnessUtxo_opt
        sighashType <- sighashType_opt
        partialSigs <- partialSigs_opt
        derivationPaths <- derivationPaths_opt
        redeemScript <- redeemScript_opt
        witnessScript <- witnessScript_opt
        scriptSig <- scriptSig_opt
        scriptWitness <- scriptWitness_opt
      } yield PartiallySignedInput(nonWitnessUtxo, witnessUtxo, sighashType, partialSigs, derivationPaths, redeemScript, witnessScript, scriptSig, scriptWitness, unknown)
    })

    private def readOutputs(input: InputStream, expectedCount: Int): Try[Seq[PartiallySignedOutput]] = trySequence((0 until expectedCount).map(_ => readOutput(input)))

    private def readOutput(input: InputStream): Try[PartiallySignedOutput] = readDataMap(input).flatMap(entries => {
      val keyTypes = Set(0x00, 0x01, 0x02).map(_.toByte)
      val (known, unknown) = entries.partition(entry => entry.key.headOption.exists(keyTypes.contains))
      val redeemScript_opt: Try[Option[List[ScriptElt]]] = known.find(_.key.head == 0x00).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt redeem script key must contain exactly 1 byte"))
        case DataEntry(_, value) => Success(Some(Script.parse(value)))
      }.getOrElse(Success(None))
      val witnessScript_opt: Try[Option[List[ScriptElt]]] = known.find(_.key.head == 0x01).map {
        case DataEntry(key, _) if key.length != 1 => Failure(new IllegalArgumentException("psbt witness script key must contain exactly 1 byte"))
        case DataEntry(_, value) => Success(Some(Script.parse(value)))
      }.getOrElse(Success(None))
      val derivationPaths_opt: Try[Map[PublicKey, KeyPathWithMaster]] = trySequence(known.filter(_.key.head == 0x02).map {
        case DataEntry(_, value) if value.length < 4 || value.length % 4 != 0 => Failure(new IllegalArgumentException("psbt bip32 derivation must contain master key fingerprint and child indexes"))
        case DataEntry(key, value) =>
          val publicKey = PublicKey(key.tail, checkValid = true)
          val masterKeyFingerprint = Protocol.uint32(value.take(4), ByteOrder.BIG_ENDIAN)
          val childCount = (value.length.toInt / 4) - 1
          val derivationPath = KeyPath((0 until childCount).map(i => Protocol.uint32(value.slice(4 * (i + 1), 4 * (i + 2)), ByteOrder.LITTLE_ENDIAN)))
          Success(publicKey, KeyPathWithMaster(masterKeyFingerprint, derivationPath))
      }).map(_.toMap)
      for {
        redeemScript <- redeemScript_opt
        witnessScript <- witnessScript_opt
        derivationPaths <- derivationPaths_opt
      } yield PartiallySignedOutput(redeemScript, witnessScript, derivationPaths, unknown)
    })

    @tailrec
    private def readDataMap(input: InputStream, entries: Seq[DataEntry] = Nil): Try[Seq[DataEntry]] = readDataEntry(input) match {
      case Success(Some(entry)) => readDataMap(input, entry +: entries)
      case Success(None) => if (entries.map(_.key).toSet.size != entries.size) {
        Failure(new IllegalArgumentException("psbt must not contain duplicate keys"))
      } else {
        Success(entries)
      }
      case Failure(ex) => Failure(ex)
    }

    private def readDataEntry(input: InputStream): Try[Option[DataEntry]] = Try {
      Protocol.varint(input) match {
        case 0 =>
          // 0x00 is used as separator to mark the end of a data map.
          None
        case keyLength =>
          val key = input.readNBytes(keyLength.toInt)
          val value = input.readNBytes(Protocol.varint(input).toInt)
          Some(DataEntry(ByteVector(key), ByteVector(value)))
      }
    }

    private def trySequence[T](elems: Seq[Try[T]]): Try[Seq[T]] = elems.foldLeft(Success(Seq.empty): Try[Seq[T]]) {
      case (Failure(ex), _) => Failure(ex)
      case (Success(_), Failure(ex)) => Failure(ex)
      case (Success(prev), Success(cur)) => Success(prev :+ cur)
    }

    def write(psbt: Psbt, output: OutputStream): Unit = {
      Protocol.writeBytes(Array[Byte](0x70, 0x73, 0x62, 0x74), output) // magic bytes
      Protocol.writeUInt8(0xff, output) // separator
      writeGlobal(psbt.global, output)
      writeInputs(psbt.inputs, output)
      writeOutputs(psbt.outputs, output)
    }

    private def writeGlobal(global: Global, output: OutputStream): Unit = {
      writeDataEntry(DataEntry(hex"00", Transaction.write(global.tx)), output)
      global.extendedPublicKeys.foreach(xpub => {
        val key = new ByteArrayOutputStream()
        Protocol.writeUInt8(0x01, key) // key type
        Protocol.writeUInt32(xpub.prefix, key, ByteOrder.BIG_ENDIAN)
        DeterministicWallet.write(xpub.extendedPublicKey, key)
        val value = new ByteArrayOutputStream()
        Protocol.writeUInt32(xpub.masterKeyFingerprint, value, ByteOrder.BIG_ENDIAN)
        xpub.extendedPublicKey.path.foreach(child => Protocol.writeUInt32(child, value, ByteOrder.LITTLE_ENDIAN))
        writeDataEntry(DataEntry(ByteVector(key.toByteArray), ByteVector(value.toByteArray)), output)
      })
      if (global.version > 0) {
        writeDataEntry(DataEntry(hex"fb", Protocol.writeUInt32(global.version, ByteOrder.LITTLE_ENDIAN)), output)
      }
      global.unknown.foreach(entry => writeDataEntry(entry, output))
      Protocol.writeUInt8(0x00, output) // separator
    }

    private def writeInputs(inputs: Seq[Psbt.PartiallySignedInput], output: OutputStream): Unit = inputs.foreach(input => {
      input.nonWitnessUtxo.foreach(tx => writeDataEntry(DataEntry(hex"00", Transaction.write(tx)), output))
      input.witnessUtxo.foreach(txOut => writeDataEntry(DataEntry(hex"01", TxOut.write(txOut)), output))
      sortPublicKeys(input.partialSigs).foreach { case (publicKey, signature) => writeDataEntry(DataEntry(0x02.toByte +: publicKey.value, signature), output) }
      input.sighashType.foreach(sighashType => writeDataEntry(DataEntry(hex"03", Protocol.writeUInt32(sighashType, ByteOrder.LITTLE_ENDIAN)), output))
      input.redeemScript.foreach(redeemScript => writeDataEntry(DataEntry(hex"04", Script.write(redeemScript)), output))
      input.witnessScript.foreach(witnessScript => writeDataEntry(DataEntry(hex"05", Script.write(witnessScript)), output))
      sortPublicKeys(input.derivationPaths).foreach {
        case (publicKey, path) =>
          val key = 0x06.toByte +: publicKey.value
          val value = Protocol.writeUInt32(path.masterKeyFingerprint, ByteOrder.BIG_ENDIAN) ++ ByteVector.concat(path.keyPath.map(childNumber => Protocol.writeUInt32(childNumber, ByteOrder.LITTLE_ENDIAN)))
          writeDataEntry(DataEntry(key, value), output)
      }
      input.scriptSig.foreach(scriptSig => writeDataEntry(DataEntry(hex"07", Script.write(scriptSig)), output))
      input.scriptWitness.foreach(scriptWitness => writeDataEntry(DataEntry(hex"08", ScriptWitness.write(scriptWitness)), output))
      input.unknown.foreach(entry => writeDataEntry(entry, output))
      Protocol.writeUInt8(0x00, output) // separator
    })

    private def writeOutputs(outputs: Seq[Psbt.PartiallySignedOutput], out: OutputStream): Unit = outputs.foreach(output => {
      output.redeemScript.foreach(redeemScript => writeDataEntry(DataEntry(hex"00", Script.write(redeemScript)), out))
      output.witnessScript.foreach(witnessScript => writeDataEntry(DataEntry(hex"01", Script.write(witnessScript)), out))
      sortPublicKeys(output.derivationPaths).foreach {
        case (publicKey, path) =>
          val key = 0x02.toByte +: publicKey.value
          val value = Protocol.writeUInt32(path.masterKeyFingerprint, ByteOrder.BIG_ENDIAN) ++ ByteVector.concat(path.keyPath.map(childNumber => Protocol.writeUInt32(childNumber, ByteOrder.LITTLE_ENDIAN)))
          writeDataEntry(DataEntry(key, value), out)
      }
      output.unknown.foreach(entry => writeDataEntry(entry, out))
      Protocol.writeUInt8(0x00, out) // separator
    })

    private def writeDataEntry(entry: DataEntry, output: OutputStream): Unit = {
      Protocol.writeVarint(entry.key.length, output)
      Protocol.writeBytes(entry.key, output)
      Protocol.writeVarint(entry.value.length, output)
      Protocol.writeBytes(entry.value, output)
    }

    /** We use lexicographic ordering on the public keys. */
    private def sortPublicKeys[T](publicKeys: Map[PublicKey, T]): Seq[(PublicKey, T)] = publicKeys.toSeq.sortWith {
      case ((pk1, _), (pk2, _)) => LexicographicalOrdering.isLessThan(pk1.value, pk2.value)
    }

  }

}
