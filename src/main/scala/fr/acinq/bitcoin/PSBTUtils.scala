package fr.acinq.bitcoin

object PSBTUtils {

  final val PSBD_MAGIC = 0x70736274
  final val GLOBAL_SEPARATOR = 0xff
  final val MAP_SEPARATOR = 0x00

  class GlobalTypes extends Enumeration {
    val transaction = Value(0x00, "Transaction type")
    val redeemScript = Value(0x01, "Redeem script type")
    val witnessScript = Value(0x02, "Witness script type")
    val bip32Data = Value(0x03, "BIP32 data type")
    val PSBTInputsNumber = Value(0x04, "Number of inputs of the PSBT type")
  }

  class InputTypes extends Enumeration {
    val nonWitnessUTXO = Value(0x00, "Non witness UTXO type")
    val witnessUTXO = Value(0x01, "Witness UTXO type")
    val partialSignature = Value(0x02, "Partial signature type")
    val sighashType = Value(0x03, "Sighash type")
    val inputIndex = Value(0x04, "Input index type")
  }


}
