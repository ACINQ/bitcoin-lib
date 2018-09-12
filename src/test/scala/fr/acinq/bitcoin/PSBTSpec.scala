package fr.acinq.bitcoin

import java.io.ByteArrayOutputStream
import fr.acinq.bitcoin.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoin.PSBT.{MapEntry, PartiallySignedInput}
import org.scalatest.FlatSpec
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class PSBTSpec extends FlatSpec{

  val dummyData = MapEntry(0xfa, BinaryData("426974636f696e20726f636b7321"))
  val dummyData2 = MapEntry(0xfb, BinaryData("436974636f696e20726f636b7322"))

  it should "fail to deserialize invalid PSBTs" in {

    // Not in PSBT format
    val invalidNetworkPSBT = "AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA=="
    // PSBT missing outputs
    val missingOutputsPSBT = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA=="
    // PSBT where one input has a filled scriptSig in the unsigned tx.
    val invalidPSBT = "cHNidP8BAP0KAQIAAAACqwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QAAAAAakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpL+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAABASAA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHhwEEFgAUhdE1N/LiZUBaNNuvqePdoB+4IwgAAAA="
    // PSBT where inputs and outputs are provided but without an unsigned tx.
    val invalidPSBT2 = "cHNidP8AAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA=="
    // PSBT with duplicate keys in an input
    val invalidPSBT3 = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQA/AgAAAAH//////////////////////////////////////////wAAAAAA/////wEAAAAAAAAAAANqAQAAAAAAAAAA"

    assert(Try(PSBT.read64(invalidNetworkPSBT)).isFailure)
    assert(Try(PSBT.read64(missingOutputsPSBT)).isFailure)
    assert(Try(PSBT.read64(invalidPSBT)).isFailure)
    assert(Try(PSBT.read64(invalidPSBT2)).isFailure)
    assert(Try(PSBT.read64(invalidPSBT3)).isFailure)

  }

  it should "deserialize a PSBT" in {

    //PSBT with one P2PKH input. Outputs are empty
    val firstPsbt = PSBT.read64("cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA")

    assert(firstPsbt.inputs.size == 1)
    assert(firstPsbt.inputs.head.nonWitnessOutput.isDefined)
    assert(firstPsbt.inputs.head.witnessOutput.isEmpty)
    assert(firstPsbt.tx.txIn.size == 1)
    assert(!firstPsbt.tx.txIn.head.isFinal)
    assert(firstPsbt.outputs.size == 2)
    firstPsbt.outputs.foreach(out => assert(out.redeemScript.isEmpty && out.witnessScript.isEmpty))

    // PSBT with one P2PKH input and one P2SH-P2WPKH input. First input is signed and finalized. Outputs are empty.
    val secondPsbt = PSBT.read64("cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA")

    assert(secondPsbt.inputs.size == 2)
    assert(secondPsbt.inputs(0).nonWitnessOutput.isEmpty)
    assert(secondPsbt.inputs(0).witnessOutput.isEmpty)
    assert(secondPsbt.inputs(0).witnessScript.isEmpty)
    assert(secondPsbt.inputs(0).redeemScript.isEmpty)
    assert(secondPsbt.inputs(0).finalScriptWitness.isEmpty)
    assert(secondPsbt.inputs(0).finalScriptSig.isDefined)

    //PSBT with one P2PKH input which has a non-final scriptSig and has a sighash type specified. Outputs are empty.
    val thirdPSBT = PSBT.read64("cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQMEAQAAAAAAAA==")

    assert(thirdPSBT.inputs.size == 1)
    assert(thirdPSBT.inputs(0).nonWitnessOutput.isDefined)
    assert(thirdPSBT.inputs(0).sighashType.isDefined)

    //PSBT with one P2PKH input and one P2SH-P2WPKH input both with non-final scriptSigs. P2SH-P2WPKH input's redeemScript is available. Outputs filled.
    val fourthPSBT = PSBT.read64("cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEA3wIAAAABJoFxNx7f8oXpN63upLN7eAAMBWbLs61kZBcTykIXG/YAAAAAakcwRAIgcLIkUSPmv0dNYMW1DAQ9TGkaXSQ18Jo0p2YqncJReQoCIAEynKnazygL3zB0DsA5BCJCLIHLRYOUV663b8Eu3ZWzASECZX0RjTNXuOD0ws1G23s59tnDjZpwq8ubLeXcjb/kzjH+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIACICAurVlmh8qAYEPtw94RbN8p1eklfBls0FXPaYyNAr8k6ZELSmumcAAACAAAAAgAIAAIAAIgIDlPYr6d8ZlSxVh3aK63aYBhrSxKJciU9H2MFitNchPQUQtKa6ZwAAAIABAACAAgAAgAA=")

    assert(fourthPSBT.inputs.size == 2)
    assert(fourthPSBT.inputs(0).nonWitnessOutput.isDefined) //first input is P2PKH
    assert(fourthPSBT.inputs(1).redeemScript.isDefined)     //second input is P2SH
    assert(fourthPSBT.outputs.size == 2)
    assert(fourthPSBT.outputs.head.bip32Data.nonEmpty)

    //PSBT with one P2SH-P2WSH input of a 2-of-2 multisig, redeemScript, witnessScript, and keypaths are available. Contains one signature.
    val fifthPSBT = PSBT.read64("cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA=")

    assert(fifthPSBT.inputs.size == 1)
    assert(fifthPSBT.inputs.head.bip32Data.size == 2)
    assert(fifthPSBT.inputs.head.redeemScript.isDefined)
    assert(fifthPSBT.inputs.head.witnessOutput.isDefined)
    assert(fifthPSBT.inputs.head.witnessScript.isDefined)
    assert(fifthPSBT.inputs.head.partialSigs.size == 1)

  }

  it should "serialize into PSBT format" in {
    val out = new ByteArrayOutputStream()

    val rawPSBT = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQMEAQAAAAAAAA=="
    val psbt = PSBT.read64(rawPSBT)
    PSBT.write(psbt, out)

    val serializedPsbt = toBase64String(out.toByteArray)

    assert(Try(PSBT.read64(serializedPsbt)).isSuccess)
    assert(serializedPsbt == rawPSBT)

    val psbtWithUnknowns = psbt.copy(
      inputs = psbt.inputs.map(_.copy(unknowns = Seq(dummyData))),
      outputs = psbt.outputs.map(_.copy(unknowns = Seq(dummyData))),
      unknowns = Seq(dummyData)
    )

    out.reset()
    PSBT.write(psbtWithUnknowns, out)
    val rawWithUnknowns = toBase64String(out.toByteArray)

    val serializedWithUnknowns = PSBT.read64(rawWithUnknowns)

    assert(serializedWithUnknowns.unknowns.nonEmpty)
    assert(serializedWithUnknowns.inputs.head.unknowns.nonEmpty)
    assert(serializedWithUnknowns.outputs.head.unknowns.nonEmpty)

    //PSBT with an input with bip32 data, witness script and redeem script
    val rawRichPsbt = "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA="
    val richPsbt = PSBT.read64(rawRichPsbt)

    out.reset()
    //now serialize it
    PSBT.write(richPsbt, out)

    val serializedRich = toBase64String(out.toByteArray)
    //de serialize it again and check its properties
    val deserializedRich = PSBT.read64(serializedRich)

    assert(deserializedRich.inputs.size == 1)
    assert(deserializedRich.inputs.head.bip32Data.size == 2)
    assert(deserializedRich.inputs.head.bip32Data.head._1.toString == "03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46")

    val fingerprint = BinaryData(Protocol.writeUInt32(deserializedRich.inputs.head.bip32Data.head._2.fingerprint))
    assert(fingerprint.toString == "b4a6ba67")
    assert(deserializedRich.inputs.head.bip32Data.head._2.hdKeyPath.toString == "m/0'/0'/4'")

    assert(serializedRich == rawRichPsbt)
  }

  //[{"txid":"75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858","vout":0},{"txid":"1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83", "vout":1}], [{"bcrt1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjdqpxskv":1.49990000}, {"bcrt1qqzh2ngh97ru8dfvgma25d6r595wcwqy0cee4cc": 1}]
  it should "create a PSBT given the inputs/outputs" in {
    val expectedRawPsbt = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="
    val expectedPsbt = PSBT.read64(expectedRawPsbt)


    val inputs = Seq(
      TxIn(OutPoint(BinaryData("75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858").reverse, 0), Nil, 0xffffffffL),
      TxIn(OutPoint(BinaryData("1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83").reverse, 1), Nil, 0xffffffffL)
    )

    val toAddress = Bech32.decodeWitnessAddress("bcrt1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjdqpxskv")._3
    val toAddress2 = Bech32.decodeWitnessAddress("bcrt1qqzh2ngh97ru8dfvgma25d6r595wcwqy0cee4cc")._3

    val outputs = Seq(
      TxOut(149990000 satoshi, OP_0 :: OP_PUSHDATA(toAddress) :: Nil),
      TxOut(100000000 satoshi, OP_0 :: OP_PUSHDATA(toAddress2) :: Nil)
    )

    val psbt = PSBT.createPSBT(inputs, outputs, txFormatVersion = 2) //reference test use version 2

    val out = new ByteArrayOutputStream()
    PSBT.write(psbt, out)

    assert(expectedPsbt.tx.txIn.head == psbt.tx.txIn.head)
    assert(expectedPsbt.tx.txIn.tail.head == psbt.tx.txIn.tail.head)
    assert(toBase64String(out.toByteArray) == expectedRawPsbt)

  }

  it should "merge the records of two PSBT according to the spec" in {

    val firstPSBT = PSBT.read64("cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA==")
    val secondPSBT = PSBT.read64("cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=")

    val expectedRawMerged = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    val expectedPSBT = PSBT.read64(expectedRawMerged)

    val merged = PSBT.mergePSBT(firstPSBT, secondPSBT)

    assert(merged.inputs.size == 2)
    assert(merged.inputs.size == expectedPSBT.inputs.size)

    assert(merged.inputs.head == expectedPSBT.inputs.head)
    assert(merged.inputs.tail.head == expectedPSBT.inputs.tail.head)

    assert(merged.outputs.size == 2)
    assert(merged.outputs.size == expectedPSBT.outputs.size)

    assert(merged.outputs.head == expectedPSBT.outputs.head)
    assert(merged.outputs.tail.head == expectedPSBT.outputs.tail.head)

    assert(merged.tx == expectedPSBT.tx)
    assert(merged.unknowns.size == 0)

    //
    //  Test field merging
    //

    val firstWithDummy = firstPSBT.copy(unknowns = Seq(dummyData2, dummyData))
    val secondWithDummy = secondPSBT.copy(unknowns = Seq(dummyData))

    val combined = PSBT.mergePSBT(firstWithDummy, secondWithDummy)

    //Unknowns must be merged dropping duplicate records
    assert(combined.unknowns.size == 2)
    assert(combined.unknowns.exists(_.key == dummyData.key))
    assert(combined.unknowns.exists(_.key == dummyData2.key))

  }

  it should "[SIGNER] make signatures for an input if possible" in {
    val out = new ByteArrayOutputStream()
    val expectedResult = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    val priv1 = PrivateKey.fromBase58("cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr", Base58.Prefix.SecretKeyTestnet)
    val priv2 = PrivateKey.fromBase58("cR6SXDoyfQrcp4piaiHE97Rsgta9mNhGTen9XeonVgwsh4iSgw6d", Base58.Prefix.SecretKeyTestnet)

    val psbt = PSBT.read64("cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAQMEAQAAAAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAAQMEAQAAAAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA")

    val signed = PSBT.signPSBT(psbt, Seq(priv1, priv2))
    PSBT.write(signed, out)

    assert(toBase64String(out.toByteArray) == expectedResult)

  }

  it should "finalize a PSBT as per spec" in {

    val expectedRawFinalized = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    val expectedFinalized = PSBT.read64(expectedRawFinalized)

    //That's the resulting serialized PSBT from the merge operation
    val input = PSBT.read64("cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA")

    assert(input.inputs(0).finalScriptSig.isEmpty)

    val finalized = PSBT.finalizePSBT(input)

    val out = new ByteArrayOutputStream()
    PSBT.write(finalized, out)

    assert(toBase64String(out.toByteArray) == expectedRawFinalized)

    assert(finalized.tx == expectedFinalized.tx)

    //Props of the expected finalized psbt input
    assert(finalized.inputs(0).finalScriptWitness == expectedFinalized.inputs(0).finalScriptWitness)
    assert(finalized.inputs(0).finalScriptSig == expectedFinalized.inputs(0).finalScriptSig)
    assert(finalized.inputs(0).nonWitnessOutput == expectedFinalized.inputs(0).nonWitnessOutput)
    assert(finalized.inputs(0).witnessOutput == expectedFinalized.inputs(0).witnessOutput)
    assert(finalized.inputs(0).redeemScript == expectedFinalized.inputs(0).redeemScript)
    assert(finalized.inputs(0).witnessScript  == expectedFinalized.inputs(0).witnessScript)
    assert(finalized.inputs(0).sighashType == expectedFinalized.inputs(0).sighashType)
    assert(finalized.inputs(0).partialSigs == expectedFinalized.inputs(0).partialSigs)
    assert(finalized.inputs(0).bip32Data == expectedFinalized.inputs(0).bip32Data)

    assert(finalized.inputs(1).finalScriptSig == expectedFinalized.inputs(1).finalScriptSig)
    assert(finalized.inputs(1).finalScriptWitness.map(ScriptWitness.write) == expectedFinalized.inputs(1).finalScriptWitness.map(ScriptWitness.write))
    assert(finalized.inputs(1).nonWitnessOutput == expectedFinalized.inputs(1).nonWitnessOutput)
    assert(finalized.inputs(1).witnessOutput == expectedFinalized.inputs(1).witnessOutput)
    assert(finalized.inputs(1).redeemScript == expectedFinalized.inputs(1).redeemScript)
    assert(finalized.inputs(1).witnessScript  == expectedFinalized.inputs(1).witnessScript)
    assert(finalized.inputs(1).sighashType == expectedFinalized.inputs(1).sighashType)
    assert(finalized.inputs(1).partialSigs == expectedFinalized.inputs(1).partialSigs)
    assert(finalized.inputs(1).bip32Data == expectedFinalized.inputs(1).bip32Data)

    assert(finalized.inputs.size == 2)
    assert(finalized.inputs.size == expectedFinalized.inputs.size)

    assert(finalized.inputs(0) == expectedFinalized.inputs(0))
    assert(finalized.inputs(1) == expectedFinalized.inputs(1))

    assert(finalized.outputs.size == 2)
    assert(finalized.outputs.size == expectedFinalized.outputs.size)
    assert(finalized.outputs(0) == expectedFinalized.outputs(0))
    assert(finalized.outputs(1) == expectedFinalized.outputs(1))

  }

  it should "finalize P2PKH inputs" in {
    val amount = Satoshi(50000000)
    val sigHash = SIGHASH_SINGLE
    val privKey = PrivateKey.fromBase58("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT", Base58.Prefix.SecretKeySegnet)
    val pubKey = privKey.publicKey
    //output script to be spent
    val scriptPubKey = Script.pay2pkh(pubKey)

    //transaction containing the UTXO
    val prevTx = Transaction(version = 1, txIn = Nil, txOut = TxOut(amount, scriptPubKey) :: Nil, lockTime = 0)

    //Create an input spending the UTXO and create a PSBT with it
    val spendingInput = Seq(TxIn(OutPoint(prevTx, 0), sequence = 0xFFFFFFFF, signatureScript = Nil))
    val newlyCreatedOut = Seq(TxOut(amount, Script.pay2wpkh(pubKey)))
    val psbt = PSBT.createPSBT(inputs = spendingInput, outputs = newlyCreatedOut)

    //make signature for input 0 of the PSBT transaction
    val sig = Transaction.signInput(psbt.tx, 0, scriptPubKey, sigHash, amount, SigVersion.SIGVERSION_BASE, privKey)

    //add the signature and the related data to the psbt
    val psbtWithSig = psbt.copy(inputs = Seq(PartiallySignedInput(
      nonWitnessOutput = Some(prevTx),
      redeemScript = Some(scriptPubKey.toList),
      partialSigs = Map(pubKey -> sig),
      sighashType = Some(sigHash)
    )))

    //finalize the psbt
    val finalized = PSBT.finalizePSBT(psbtWithSig)

    //check if final scriptSig is defined
    assert(finalized.inputs.head.finalScriptSig.isDefined)

  }

  it should "sign and finalize native P2WPKH" in {
    val sigHash = SIGHASH_ALL
    val priv1 = PrivateKey.fromBase58("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT", Base58.Prefix.SecretKeySegnet)
    val pub1 = priv1.publicKey
    //output script to be spent
    val scriptPubKey = Script.pay2wpkh(pub1)

    //send 0.39 BTC to P2WPK output
    val prevTx = Transaction(version = 1, txIn = Nil, txOut = TxOut(0.39 btc, scriptPubKey) :: Nil, lockTime = 0)

    val utxo = prevTx.txOut.head
    val spendingInput = TxIn(OutPoint(prevTx.hash, 0), sequence = 0xffffffffL, signatureScript = Nil, witness = ScriptWitness.empty)
    val newlyCreatedOut = TxOut(0.38 btc, Script.pay2pkh(pub1))

    val psbt = PSBT.createPSBT(Seq(spendingInput), Seq(newlyCreatedOut)).copy(inputs = Seq(PartiallySignedInput(
      witnessOutput = Some(utxo),
      witnessScript = Some(Script.parse(utxo.publicKeyScript)),
      sighashType = Some(sigHash)
    )))

    val signed = PSBT.signPSBT(psbt, Seq(priv1))

    //a signature corresponding to priv1.publicKey has been added to the PSBT
    assert(signed.inputs(0).partialSigs.get(priv1.publicKey).isDefined)

    //finalizing the PSBT will also run the script and check the outcome
    val finalized = PSBT.finalizePSBT(signed)

    assert(finalized.inputs.head.finalScriptWitness.isDefined)
    assert(finalized.inputs.head.finalScriptSig.isEmpty)

  }

  it should "sign and finalize native P2WSH inputs" in {
    val sigHash = SIGHASH_ALL
    val priv1 = PrivateKey.fromBase58("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT", Base58.Prefix.SecretKeySegnet)
    val priv2 = PrivateKey.fromBase58("QUpr3G5ia7K7txSq5k7QpgTfNy33iTQWb1nAUgb77xFesn89xsoJ", Base58.Prefix.SecretKeySegnet)
    val priv3 = PrivateKey.fromBase58("QX3AN7b3WCAFaiCvAS2UD7HJZBsFU6r5shjfogJu55411hAF3BVx", Base58.Prefix.SecretKeySegnet)

    //The UTXO containing the P2WSH script
    val redeemScript = Script.createMultiSigMofN(2, Seq(priv2.publicKey, priv3.publicKey))
    val prevTx = Transaction(version = 1, txIn = Nil, txOut = TxOut(0.49 btc, Script.pay2wsh(redeemScript)) :: Nil, lockTime = 0)

    val utxo = prevTx.txOut.head
    val spendingInput = TxIn(OutPoint(prevTx.hash, 0), sequence = 0xffffffffL, signatureScript = Nil)
    val newlyCreatedOut = TxOut(0.48 btc, Script.pay2pkh(priv1.publicKey))

    val psbt = PSBT.createPSBT(Seq(spendingInput), Seq(newlyCreatedOut)).copy(inputs = Seq(PartiallySignedInput(
      witnessScript = Some(redeemScript.toList),
      witnessOutput = Some(utxo),
      sighashType = Some(sigHash)
    )))

    val sig2 = Transaction.signInput(psbt.tx, 0, Script.write(redeemScript), sigHash, utxo.amount, SigVersion.SIGVERSION_WITNESS_V0, priv2)
    val sig3 = Transaction.signInput(psbt.tx, 0, Script.write(redeemScript), sigHash, utxo.amount, SigVersion.SIGVERSION_WITNESS_V0, priv3)

    val signed = PSBT.signPSBT(psbt, Seq(priv3, priv2))

    assert(!signed.inputs(0).partialSigs.isEmpty)
    assert(signed.inputs(0).partialSigs.get(priv2.publicKey).get == sig2)
    assert(signed.inputs(0).partialSigs.get(priv3.publicKey).get == sig3)

    val finalized = PSBT.finalizePSBT(signed)

    assert(finalized.inputs.head.finalScriptWitness.isDefined)
    assert(finalized.inputs.head.finalScriptSig.isEmpty)
    assert(finalized.inputs.head.witnessScript.isEmpty)

  }

  it should "finalize P2SH-P2WKH inputs" in {
    val priv1 = PrivateKey.fromBase58("QRY5zPUH6tWhQr2NwFXNpMbiLQq9u2ztcSZ6RwMPjyKv36rHP2xT", Base58.Prefix.SecretKeySegnet)
    val pub1 = priv1.publicKey

    // p2wpkh script
    val script = Script.write(Script.pay2wpkh(pub1))
    //Sends 0.5 btc to the above 'p2shAddress'
    val prevTx = Transaction.read("010000000175dd435bf25e5d77567272f7d6eefcf37b7156b78bb233490140d6fa7545cfca010000006a47304402206e601a482b301141cb3a1712c18729fa1f1731fce5c4205ac9d344af38bb24bf022003fe70edcbd1a5b3957b3c939e583739eadb8de8d3d2cc2ad2903b19c991cb80012102ba2558223d7cd5df2d8decc4506a62ccaa96159f685360335c280952b25e7adefeffffff02692184df000000001976a9148b3ee15d631122010d31e1774aa318ca9ca8b67088ac80f0fa020000000017a9143e73638f202bb880a28e8df1946adc3058227d11878c730000", Protocol.PROTOCOL_VERSION)

    val utxo = prevTx.txOut(1)
    val spendingInput = TxIn(OutPoint(prevTx.hash, 1), sequence = 0xffffffffL, signatureScript = Seq.empty)
    val newlyCreatedOutput = TxOut(0.49 btc, OP_0 :: OP_PUSHDATA(Crypto.hash160(pub1.toBin)) :: Nil)

    val psbt = PSBT.createPSBT(inputs = Seq(spendingInput), outputs = Seq(newlyCreatedOutput))

    val signatureScriptPubKey = Script.pay2pkh(pub1)
    val sig = Transaction.signInput(psbt.tx, 0, signatureScriptPubKey, SIGHASH_ALL, utxo.amount, SigVersion.SIGVERSION_WITNESS_V0, priv1)

    val updated = psbt.copy(inputs = Seq(PartiallySignedInput(
      witnessOutput = Some(utxo),
      redeemScript = Some(Script.parse(script)),
      witnessScript = Some(Script.parse(script)),
      sighashType = Some(SIGHASH_ALL),
      partialSigs = Map(pub1 -> sig)
    )))

    val finalized = PSBT.finalizePSBT(updated)

    assert(finalized.inputs.head.finalScriptSig.isDefined)
    assert(finalized.inputs.head.finalScriptWitness.isDefined)

  }

  it should "extract a finalized transaction" in {
    val input = PSBT.read64("cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA==")

    val extracted = PSBT.extractPSBT(input)
    val  serialized = Transaction.write(extracted)

    assert(serialized.toString == "0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000")

  }

}