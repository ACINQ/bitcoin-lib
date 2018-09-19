package fr.acinq.bitcoin

import java.io.{ByteArrayInputStream, InputStream, OutputStream}
import java.nio.ByteOrder
import Protocol._
import fr.acinq.bitcoin.Crypto.PublicKey
import fr.acinq.bitcoin.Crypto._
import fr.acinq.bitcoin.DeterministicWallet.KeyPath
import fr.acinq.bitcoin.DeterministicWallet._
import fr.acinq.bitcoin.Script.Runner
import scala.annotation.tailrec

/**
  * BIP174 Partially signed bitcoin transactions https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
  */
object PSBT {

  type Script = List[ScriptElt]

  case class KeyPathWithFingerprint(fingerprint: Long, hdKeyPath: KeyPath){
    override def toString: String = s"Fingerprint: ${BinaryData(writeUInt32(fingerprint))} KeyPath: $hdKeyPath"
  }

  case class MapEntry(key: BinaryData, value: BinaryData)

  object MapEntry {
    def apply(key: Int, value: BinaryData): MapEntry = new MapEntry(Seq(key.byteValue), value)
  }

  case class PartiallySignedInput(
    nonWitnessOutput: Option[Transaction] = None,
    witnessOutput:Option[TxOut] = None,
    redeemScript: Option[Script] = None,
    witnessScript: Option[Script] = None,
    finalScriptSig: Option[Script] = None,
    finalScriptWitness: Option[ScriptWitness] = None,
    bip32Data: Map[PublicKey, KeyPathWithFingerprint] = Map.empty,
    partialSigs: Map[PublicKey, BinaryData] = Map.empty,
    sighashType: Option[Int] = None,
    unknowns: Seq[MapEntry] = Seq.empty
  ) {

    require( !(witnessOutput.isDefined && nonWitnessOutput.isDefined), "PSBT Input can't have both witness and non withness UTXO")
    require( !(witnessScript.isDefined && witnessOutput.isEmpty), "PSBT Input with witness script must have witness output")
    require( !(finalScriptWitness.isDefined && witnessOutput.isEmpty), "PSBT Input with final script witness must have witness output")

    override def toString: String = {
      s"""Input(
         |  nonWitnessOutput: $nonWitnessOutput
         |  witnessOutput: $witnessOutput
         |  redeemScript: $redeemScript
         |  witnessScript: $witnessScript
         |  finalScriptSig: $finalScriptSig
         |  finalScriptWitness: $finalScriptWitness
         |  bip32Data: $bip32Data
         |  partialSigs: $partialSigs
         |  sighashType: $sighashType
         |  unknowns: ${unknowns.size}
         )""".stripMargin
    }

    /**
      * Merges together 2 PSBT inputs, if a witness output is found the non witness is cleared.
      *
      * @param psbtIn
      * @return
      */
    def merge(psbtIn: PartiallySignedInput): PartiallySignedInput = {

      //see logic in sign.cpp#PSBTInput::Merge
      val (nonWitnessUtxo, witnessUtxo) = (nonWitnessOutput, witnessOutput) match {
        case (_, Some(_))       => (None, witnessOutput)
        case (Some(_), None)    => if(psbtIn.witnessOutput.isDefined) (None, psbtIn.witnessOutput) else (nonWitnessOutput, None)
        case (None, None)       => if(psbtIn.witnessOutput.isDefined) (None, psbtIn.witnessOutput) else (None, None)
      }

      PartiallySignedInput(
        nonWitnessOutput = nonWitnessUtxo,
        witnessOutput = witnessUtxo,
        redeemScript = if(redeemScript.isEmpty) psbtIn.redeemScript else redeemScript,
        witnessScript = if(witnessScript.isEmpty) psbtIn.witnessScript else witnessScript,
        finalScriptSig = if(finalScriptSig.isEmpty) psbtIn.finalScriptSig else finalScriptSig,
        finalScriptWitness = if(finalScriptWitness.isEmpty) psbtIn.finalScriptWitness else finalScriptWitness,
        partialSigs = partialSigs ++ psbtIn.partialSigs,
        sighashType = sighashType.orElse(psbtIn.sighashType),
        bip32Data = bip32Data ++ psbtIn.bip32Data,
        unknowns = removeDuplicatesFromPsbtMap(unknowns ++ psbtIn.unknowns)
      )
    }

    def hasFinalSigs: Boolean = finalScriptSig.isDefined || finalScriptWitness.isDefined

    def signIfPossible(tx: Transaction, index: Int,keys: Seq[PrivateKey]): PartiallySignedInput = {

      if(hasFinalSigs) return this

      (redeemScript, witnessScript) match {
        //P2PKH/P2SH
        case (Some(redeem), None) =>
          val prevTx = nonWitnessOutput.getOrElse(return this)
          val utxo   = prevTx.txOut(tx.txIn(index).outPoint.index.toInt)
          val scriptPubKey = Script.parse(utxo.publicKeyScript)
          require(tx.txIn(index).outPoint.hash == prevTx.hash, s"This input references another transaction than ${prevTx.hash}")

          Script.isPayToScript(scriptPubKey) match {
            case true   =>
              if(Script.write(scriptPubKey) != Script.write(Script.pay2sh(redeem))) return this

              val pubKeys = Script.publicKeysFromMultisigRedeem(redeem)
              val filtered = keys.filter(priv => pubKeys.contains(priv.publicKey.toBin))
              val sigs = filtered.map { privKey =>
                val sig = Transaction.signInput(tx, index, redeem, sighashType.getOrElse(SIGHASH_ALL), utxo.amount, SigVersion.SIGVERSION_BASE, privKey)
                (privKey.publicKey, sig)
              }
              this.copy(partialSigs = partialSigs ++ sigs.toMap)
            case false  =>
              val pubKeyHash = Script.publicKeyHash(redeem)
              keys.find(_.publicKey.hash160 == pubKeyHash) match {
                case None          => this
                case Some(privKey) =>
                  val sig = {
                    val s = Transaction.signInput(tx, index, redeem, sighashType.getOrElse(SIGHASH_ALL), utxo.amount, SigVersion.SIGVERSION_BASE, privKey)
                    (privKey.publicKey, s)
                  }
                  this.copy(partialSigs = partialSigs + sig)
              }
          }
        //P2WPKH/P2WSH
        case (None, Some(witnessProg)) =>
          val utxo = witnessOutput.getOrElse(return this)
          Script.parse(utxo.publicKeyScript) match {
            //P2WPKH
            case OP_0 :: OP_PUSHDATA(pubkeyHash, size) :: Nil if size == 20 =>
              keys.find(_.publicKey.hash160 == pubkeyHash) match {
                case None          => this
                case Some(privKey) =>
                  val sig = {
                    val signaturePubKeyScript = Script.pay2pkh(privKey.publicKey)
                    val s = Transaction.signInput(tx, index, signaturePubKeyScript, sighashType.getOrElse(SIGHASH_ALL), utxo.amount, SigVersion.SIGVERSION_WITNESS_V0, privKey)
                    (privKey.publicKey, s)
                  }
                  this.copy(partialSigs = partialSigs + sig)
              }
            //P2WSH
            case OP_0 :: OP_PUSHDATA(pubkeyHash, size) :: Nil if size == 32 =>
              if(utxo.publicKeyScript != Script.write(Script.pay2wsh(witnessProg))) return this
              val pubKeys = Script.publicKeysFromMultisigRedeem(witnessProg)
              val filtered = keys.filter(priv => pubKeys.contains(priv.publicKey.toBin))
              val sigs = filtered.map { privKey =>
                val sig = Transaction.signInput(tx, index, witnessProg, sighashType.getOrElse(SIGHASH_ALL), utxo.amount, SigVersion.SIGVERSION_WITNESS_V0, privKey)
                (privKey.publicKey, sig)
              }
              this.copy(partialSigs = partialSigs ++ sigs.toMap)
          }
        //nested
        case (Some(redeem), Some(witnessProg)) =>
          val utxo = witnessOutput.getOrElse(return this)
          val scriptPubKey = utxo.publicKeyScript
          val expectedHash = BinaryData(Script.publicKeyHash(scriptPubKey))
          val serializedRedeem = Script.write(redeem)
          if(Crypto.hash160(serializedRedeem) != expectedHash) return this

          redeem match {
            case OP_0 :: OP_PUSHDATA(data, dataLength) :: Nil if dataLength == 32 =>
              if(data != Crypto.sha256(Script.write(witnessProg))) return this
              val pubKeys = Script.publicKeysFromMultisigRedeem(witnessProg)
              val filtered = keys.filter(priv => pubKeys.contains(priv.publicKey.toBin))
              val sigs = filtered.map { privKey =>
                val sig = Transaction.signInput(tx, index, witnessProg, sighashType.getOrElse(SIGHASH_ALL), utxo.amount, SigVersion.SIGVERSION_WITNESS_V0, privKey)
                (privKey.publicKey, sig)
              }
              this.copy(partialSigs = partialSigs ++ sigs.toMap)
            case OP_0 :: OP_PUSHDATA(data, dataLength) :: Nil if dataLength == 20 =>
              keys.find(_.publicKey.hash160 == data) match {
                case None => this
                case Some(privKey) =>
                  val sig = {
                    val s = Transaction.signInput(tx, index, witnessProg, sighashType.getOrElse(SIGHASH_ALL), utxo.amount, SigVersion.SIGVERSION_WITNESS_V0, privKey)
                    (privKey.publicKey, s)
                  }
                  this.copy(partialSigs = partialSigs + sig)
              }
          }
        //not enough data to sign this input, let's just return it
        case (None, None)         => this
      }

    }

    def finalizeIfComplete(tx: Transaction, index: Int): PartiallySignedInput = {

      if(hasFinalSigs) return this

      //Try to create final script
      val (scriptSig, scriptPubKey, witness, amount) = (redeemScript, witnessScript) match {
        case (None, None) => throw new IllegalArgumentException(s"Not enough data to finalize input with index=$index")
        case (Some(redeem), None) =>
          val prevTx = nonWitnessOutput.getOrElse(throw new RuntimeException("Non witness output not found"))
          val utxo   = prevTx.txOut(index)
          val scriptPubKey = Script.parse(utxo.publicKeyScript)
          val pubkeyHash = BinaryData(Script.publicKeyHash(scriptPubKey))

          val scriptSig = Script.isPayToScript(scriptPubKey) match {
            //P2SH
            case true   =>
              //first step check the redeemScript hash
              require(Crypto.hash160(Script.write(redeemScript.get)) == pubkeyHash, "P2SH redeem script does not match expected hash")
              val multiSigPubKeys = Script.publicKeysFromMultisigRedeem(redeem)
              val sigs = multiSigPubKeys.map(pubKeyData => partialSigs.get(PublicKey(pubKeyData))).filter(_.isDefined).flatten

              //If the PSBT does not contain all the necessary signatures, abort.
              if (sigs.size < multiSigPubKeys.size) return this

              //scriptSig for multisig P2SH
              (OP_0 +: sigs.map(OP_PUSHDATA(_))) ++ (OP_PUSHDATA(Script.write(redeem)) :: Nil)
            //P2PKH
            case false  =>
              //get the signature or abort
              val (pub, sig) = partialSigs.find(el => el._1.hash160 == pubkeyHash).getOrElse(return this)
              OP_PUSHDATA(sig) :: OP_PUSHDATA(pub) :: Nil
          }
          (Script.write(scriptSig), Script.write(scriptPubKey), ScriptWitness.empty, utxo.amount)
        // P2WPKH
        case (None, Some(witnessProg)) =>

          val utxo = witnessOutput.getOrElse(throw new IllegalArgumentException("Script pubkey not found"))

          val finalWitness = Script.parse(utxo.publicKeyScript) match {
            //P2WPKH
            case OP_0 :: OP_PUSHDATA(pubkeyHash, size) :: Nil if size == 20 =>
              val (pub, sig) = partialSigs.find(el => el._1.hash160 == pubkeyHash).getOrElse(return this)
              ScriptWitness(sig :: pub.toBin :: Nil)
            //P2WSH
            case OP_0 :: OP_PUSHDATA(scriptHash, size) :: Nil if size == 32 =>
              require(scriptHash == Crypto.sha256(Script.write(witnessProg)), "Script hash does not match witnessScript")
              val pubKeys = Script.publicKeysFromMultisigRedeem(witnessProg)
              val sigs = pubKeys.map(pubKeyData => partialSigs.get(PublicKey(pubKeyData))).filter(_.isDefined).flatten
              if(sigs.size < pubKeys.size) return this

              ScriptWitness(BinaryData.empty +: sigs :+ Script.write(witnessProg))
          }

          (BinaryData.empty, utxo.publicKeyScript, finalWitness, utxo.amount)
        // nested P2SH
        case (Some(redeem), Some(witness)) =>

          val utxo = witnessOutput.getOrElse(throw new IllegalArgumentException("Script pubkey not found"))
          val scriptPubKey = utxo.publicKeyScript
          val expectedHash = BinaryData(Script.publicKeyHash(scriptPubKey))
          val serializedRedeem = Script.write(redeem)
          require(Crypto.hash160(serializedRedeem) == expectedHash, "P2SH redeem script does not match expected hash")

          redeem match {
            // P2SH - P2WSH
            case OP_0 :: OP_PUSHDATA(data, dataLength) :: Nil if dataLength == 32 =>
              require(data == Crypto.sha256(Script.write(witness)), "SHA of the witness script must match the witness program")
              val pubKeys = Script.publicKeysFromMultisigRedeem(witness)
              val sigs = pubKeys.map(pubKeyData => partialSigs.get(PublicKey(pubKeyData))).filter(_.isDefined).flatten
              if(sigs.size < pubKeys.size) return this

              val finalScriptSignature = Script.write(OP_PUSHDATA(serializedRedeem) :: Nil)
              val finalScriptWit = ScriptWitness(BinaryData.empty +: sigs :+ Script.write(witness))
              (finalScriptSignature, scriptPubKey, finalScriptWit,  utxo.amount)

            //P2SH - P2WPKH
            case OP_0 :: OP_PUSHDATA(data, dataLength) :: Nil if dataLength == 20 =>
              val (pub, sig) = partialSigs.find(el => el._1.hash160 == data).getOrElse(return this)
              val scriptSig = Script.write(OP_PUSHDATA(Script.write(redeem)) :: Nil)
              val finalWitProg = ScriptWitness(sig :: pub.toBin :: Nil)
              (scriptSig, scriptPubKey, finalWitProg,  utxo.amount)
          }
      }

      val runner = new Runner(Script.Context(tx, index, amount), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
      runner.verifyScripts(scriptSig, scriptPubKey, witness) match {
        case false => throw new IllegalArgumentException("Script execution failed")
        case true => this.copy(
          finalScriptSig = if(scriptSig.isEmpty) None else Some(Script.parse(scriptSig)),
          finalScriptWitness = if(witness.isNull) None else Some(witness),
          partialSigs = Map.empty,
          bip32Data = Map.empty,
          redeemScript = None,
          witnessScript = None,
          sighashType =  None
        )
      }

    }

  }

  case class PartiallySignedOutput(
    redeemScript: Option[Script] = None,
    witnessScript: Option[Script] = None,
    bip32Data: Map[PublicKey, KeyPathWithFingerprint] = Map.empty,
    unknowns: Seq[MapEntry] = Seq.empty
  ) {

    override def toString: String = {
      s"""
         |Output(
         |  redeemScript: $redeemScript
         |  witnessScript: $witnessScript
         |  bip32Data: $bip32Data
         |  unknowns: ${unknowns.size}
         |)
       """.stripMargin
    }

    def merge(psbtOut: PartiallySignedOutput): PartiallySignedOutput = PartiallySignedOutput(
      redeemScript = if(redeemScript.isEmpty) psbtOut.redeemScript else redeemScript,
      witnessScript = if(witnessScript.isEmpty) psbtOut.witnessScript else witnessScript,
      bip32Data = bip32Data ++ psbtOut.bip32Data,
      unknowns = removeDuplicatesFromPsbtMap(unknowns ++ psbtOut.unknowns)
    )

  }

  case class PartiallySignedTransaction(
    tx: Transaction,
    inputs: Seq[PartiallySignedInput],
    outputs: Seq[PartiallySignedOutput],
    unknowns: Seq[MapEntry] = Seq.empty
  ) {

    override def toString: String = {
      s"""
         | tx: ${tx.txid}
         | inputs: ${inputs.zipWithIndex.map{ case (in, i) => s"[$i] $in"}}
         | outputs: $outputs
       """.stripMargin
    }

  }

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

  //Reads a predetermined number of maps (as list of key/value records)
  @tailrec
  private def readMaps(counter: Int = 0, input: InputStream, acc: Seq[Seq[MapEntry]] = Seq.empty): Seq[Seq[MapEntry]] = {
    if(counter > 0) {
      readMaps(counter - 1, input, acc :+ readKeyValueMap(input))
    } else {
      acc
    }
  }

  private def assertTypedKeySize(entry: MapEntry): Unit = {
    import InputTypes._

    if(!isKeyUnknown(entry.key, InputTypes)) {
      InputTypes(entry.key.head) match {
        case NonWitnessUTXO |
             WitnessUTXO |
             InputTypes.RedeemScript |
             InputTypes.WitnessScript |
             FinalScriptWitness |
             FinalScriptSig |
             SighashType if entry.key.size > 1 =>
          throw new IllegalArgumentException(s"Invalid key size for type: ${InputTypes(entry.key.head)}")
        case _ =>
      }
    } else if(!isKeyUnknown(entry.key, OutputTypes)){
      OutputTypes(entry.key.head) match {
        case  OutputTypes.RedeemScript |
              OutputTypes.WitnessScript if entry.key.size > 1 =>
          throw new IllegalArgumentException(s"Invalid key size for type: ${OutputTypes(entry.key.head)}")
        case _ =>
      }
    }

  }

  private def removeDuplicatesFromPsbtMap(psbtMap: Seq[MapEntry]): Seq[MapEntry] = {
    //this converts the list of entries to a scala map and back to list of entries, scala maps enforce uniqueness on the key
    psbtMap.map( el => el.key -> el.value ).toMap.map{ case (k,v) => MapEntry(k, v) }.toSeq
  }

  private def assertNoDuplicates(psbtMap: Seq[MapEntry]) = {
    val setSmallerThanList = psbtMap.map(_.key).distinct.size < psbtMap.size
    require(psbtMap.size < 2 || !setSmallerThanList, "Duplicate keys not allowed") //TODO add the key
  }

  private def isKeyUnknown[T <: Enumeration](key: BinaryData, enumType: T): Boolean = {
    !enumType.values.map(_.id).contains(key.head) // { 0x00, 0x01, 0x02, 0x03, 0x04 }
  }

  private def mapEntryToKeyPaths(entry: MapEntry):(PublicKey, KeyPathWithFingerprint) = {
    val pubKey = PublicKey(entry.key.drop(1))
    require(isPubKeyValid(pubKey.data), "Invalid pubKey parsed")

    val derivationPaths = entry
      .value
      .grouped(4) //groups of 4 bytes (32 bit uint)
      .map(uint32(_, ByteOrder.LITTLE_ENDIAN))
      .toSeq

    //Store the first integer separately as fingerprint
    pubKey -> KeyPathWithFingerprint(derivationPaths.head, KeyPath(derivationPaths.tail))
  }

  private def mapEntryToScript(entry: MapEntry): Script = Script.parse(entry.value)

  def read64(input: String, protocolVersion: Long = PROTOCOL_VERSION): PartiallySignedTransaction = {
    read(new ByteArrayInputStream(fromBase64String(input)), protocolVersion)
  }

  def read(input: InputStream, protocolVersion: Long = PROTOCOL_VERSION): PartiallySignedTransaction = {
    import GlobalTypes._
    import InputTypes._

    val psbtMagic = uint32(input, ByteOrder.BIG_ENDIAN)
    val separator = uint8(input)
    require(psbtMagic == PSBD_MAGIC && separator == HEADER_SEPARATOR, s"PSBT header not valid '$psbtMagic|$separator'")

    //Read exactly one map for globals
    val globalMap = readKeyValueMap(input)

    //check for uniqueness of the Transaction record type and the typed key size
    val tx = globalMap.filter(_.key.head == TransactionType.id) match {
      case entry :: Nil if entry.key.size == 1 => Transaction.read(entry.value, protocolVersion)
      case _        => throw new IllegalArgumentException("Invalid record Transaction record (either duplicate or wrong key size)")
    }

    tx.txIn.foreach { in =>
      require(!in.hasSigScript && !in.hasWitness, s"Non empty input(${TxIn.write(in).toString}) found in the transaction")
    }

    val globalUnknowns = globalMap.filter(el => isKeyUnknown(el.key, GlobalTypes))

    //Read as many maps as the inputs/outpus found on the unsigned transaction
    val inputMaps = readMaps(tx.txIn.size, input)
    val outputMaps = readMaps(tx.txOut.size, input)

    //Assert there are no repeated keys within each maps's scope
    assertNoDuplicates(globalMap)
    inputMaps.foreach(assertNoDuplicates)
    outputMaps.foreach(assertNoDuplicates)
    //Check the size of the key
    inputMaps.flatten.foreach(assertTypedKeySize)
    outputMaps.flatten.foreach(assertTypedKeySize)

    val psbis = inputMaps.zipWithIndex.map { case (inputMap, index) =>

      val nonWitOut = inputMap.find(_.key.head == NonWitnessUTXO.id).map { nonWitnessUtxoEntry =>
        Transaction.read(nonWitnessUtxoEntry.value)
      }

      nonWitOut.map { prevTx =>
        require(prevTx.txid == tx.txIn(index).outPoint.txid, "Non-witness UTXO does not match outpoint hash")
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

      PartiallySignedInput(nonWitOut, witOut, redeemScript, witScript, finRedeemScript, finWitScript, hdKeyPath, partialSig, sigHash, unknowns)
    }

    val psbtOuts = outputMaps.map { outputMap =>

      val redeemScript = outputMap.find(_.key.head == OutputTypes.RedeemScript.id).map(mapEntryToScript)
      val witScript = outputMap.find(_.key.head == OutputTypes.WitnessScript.id).map(mapEntryToScript)
      val hdKeyPaths = outputMap.filter(_.key.head == OutputTypes.Bip32Data.id).map(mapEntryToKeyPaths).toMap
      val unknowns = outputMap.filter(el => isKeyUnknown(el.key, InputTypes))

      PartiallySignedOutput(redeemScript, witScript, hdKeyPaths, unknowns)
    }

    //sanity checks
    require(psbis.size == tx.txIn.size, "Inputs provided does not match the number of inputs in transaction.")
    require(psbtOuts.size == tx.txOut.size, "Outputs provided does not match the number of outputs in transaction.")

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

    val txEntry = MapEntry(Seq(TransactionType.id.toByte), Transaction.write(psbt.tx))

    //write global map
    writeKeyValue(txEntry, out)
    psbt.unknowns.foreach(writeKeyValue(_, out))
    writeUInt8(SEPARATOR, out)

    psbt.inputs.foreach { input =>

      val redeemOut = input.nonWitnessOutput.map(tx => MapEntry(NonWitnessUTXO.id, Transaction.write(tx)))
      val witOut = input.witnessOutput.map(txOut => MapEntry(WitnessUTXO.id, TxOut.write(txOut)))
      val redeemScript = input.redeemScript.map(script => MapEntry(RedeemScript.id, Script.write(script)))
      val witscript = input.witnessScript.map(wscript => MapEntry(WitnessScript.id, Script.write(wscript)))
      val finScriptSig = input.finalScriptSig.map(script => MapEntry(FinalScriptSig.id, Script.write(script)))
      val finScriptWit = input.finalScriptWitness.map{ wscript =>
        MapEntry(FinalScriptWitness.id, ScriptWitness.write(wscript))
      }
      val bip32Data = input.bip32Data.map { case (pubKey, keyPath) =>
        MapEntry(Bip32Data.id.byteValue +: pubKey.data, writeUInt32(keyPath.fingerprint) ++ keyPath.hdKeyPath.map(writeUInt32).flatten)
      }

      val partialSigs = input.partialSigs.map { case (pubKey, sig) =>
        MapEntry(PartialSignature.id.byteValue +: pubKey.data, sig)
      }

      val sigHash = input.sighashType.map { value =>
        MapEntry(SighashType.id, writeUInt32(value))
      }

      //Write to stream
      redeemOut.foreach(writeKeyValue(_, out))
      witOut.foreach(writeKeyValue(_, out))
      partialSigs.foreach(writeKeyValue(_, out))
      sigHash.foreach(writeKeyValue(_, out))
      redeemScript.foreach(writeKeyValue(_, out))
      witscript.foreach(writeKeyValue(_, out))
      finScriptSig.foreach(writeKeyValue(_, out))
      finScriptWit.foreach(writeKeyValue(_, out))
      bip32Data.foreach(writeKeyValue(_, out))
      input.unknowns.foreach(writeKeyValue(_, out))
      writeUInt8(SEPARATOR, out)

    }

    psbt.outputs.foreach { output =>

      val redeemScript = output.redeemScript.map(script => MapEntry(OutputTypes.RedeemScript.id, Script.write(script)))
      val witnessScript = output.witnessScript.map(wscript => MapEntry(OutputTypes.WitnessScript.id, Script.write(wscript)))
      val bip32Data = output.bip32Data.map { case (pubKey, keyPath) =>
        MapEntry(OutputTypes.Bip32Data.id.byteValue +: pubKey.data, writeUInt32(keyPath.fingerprint) ++ keyPath.hdKeyPath.map(writeUInt32).flatten)
      }

      redeemScript.foreach(writeKeyValue(_, out))
      witnessScript.foreach(writeKeyValue(_, out))
      bip32Data.foreach(writeKeyValue(_, out))
      output.unknowns.foreach(writeKeyValue(_, out))
      writeUInt8(SEPARATOR, out)

    }

  }

  /**
    *
    *
    */

  def createPSBT(inputs: Seq[TxIn], outputs: Seq[TxOut], lockTime: Long = 0, txFormatVersion: Int = 1): PartiallySignedTransaction = {
    val tx = Transaction(txFormatVersion, inputs, outputs, lockTime)

    PartiallySignedTransaction(
      tx = tx,
      inputs = tx.txIn.map(_ => PartiallySignedInput()),
      outputs = tx.txOut.map(_ => PartiallySignedOutput())
    )
  }

  def mergePSBT(firstPSBT: PartiallySignedTransaction, secondPSBT: PartiallySignedTransaction): PartiallySignedTransaction = {
    //check if they refer to the same transaction
    require(firstPSBT.tx.hash == secondPSBT.tx.hash, "Unable to merge PSBTs, they don't refer to the same transction")

    //merged inputs
    val combinedInputs= firstPSBT.inputs.zipWithIndex.map{ case (in, idx) => in.merge(secondPSBT.inputs(idx)) }

    //merged outputs
    val combinedOutputs = firstPSBT.outputs.zipWithIndex.map{ case (out, idx) => out.merge(secondPSBT.outputs(idx)) }

    //merged unknowns
    val combinedUnknowns = removeDuplicatesFromPsbtMap(firstPSBT.unknowns ++ secondPSBT.unknowns)

    PartiallySignedTransaction(firstPSBT.tx, combinedInputs, combinedOutputs, combinedUnknowns)
  }

  def signPSBT(psbt: PartiallySignedTransaction, keys: Seq[PrivateKey]): PartiallySignedTransaction = {

    psbt.copy(inputs = psbt.inputs.zipWithIndex.map { case (input, idx) =>
      input.signIfPossible(psbt.tx, idx, keys)
    })

  }

  def finalizePSBT(psbt: PartiallySignedTransaction): PartiallySignedTransaction = {

    //try to finalize the inputs if they've already been signed (partial sigs are exaustive)
    psbt.copy(inputs = psbt.inputs.zipWithIndex.map { case (input, idx) =>
      input.finalizeIfComplete(psbt.tx, idx)
    })

  }

  def extractPSBT(psbt: PartiallySignedTransaction): Transaction = {
    if(!psbt.inputs.forall(_.hasFinalSigs)){
      throw new IllegalArgumentException("PSBT inputs are not final")
    }

    //traverse the (indexed) input list carrying a transaction that is being updated with sigScript/witness
    psbt.inputs.zipWithIndex.foldLeft(psbt.tx) {
      case (tx, (PartiallySignedInput(_,_,_,_,Some(sigScript),None,_,_,_,_), index)) =>
        tx.updateSigScript(index, sigScript)
      case (tx, (PartiallySignedInput(_,_,_,_,None,Some(scriptWitness),_,_,_,_), index)) =>
        tx.updateWitness(index, scriptWitness)
      case (tx, (PartiallySignedInput(_,_,_,_,Some(sigScript),Some(scriptWitness),_,_,_,_), index)) =>
        tx.updateSigScript(index, sigScript).updateWitness(index, scriptWitness)
    }

  }


}
