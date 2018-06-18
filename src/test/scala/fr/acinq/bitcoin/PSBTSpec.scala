package fr.acinq.bitcoin

import java.io.ByteArrayOutputStream
import org.scalatest.FlatSpec
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class PSBTSpec extends FlatSpec{

  it should "fail to deserialize invalid PSBTs" in {

    // Not in PSBT format
    val invalidNetworkPSBT = "0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300"
    // PSBT missing null terminator
    val missingNullTerminatorPSBT = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab300000000"
    // PSBT with one P2PKH input and one P2SH-P2WPKH input with only the first input signed, finalized, and skipped. Input index is specified but total input count is not given.
    val invalidPSBT = "70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac0000000015013545e6e33b832c47050f24d3eeb93c9c03948bc716001485d13537f2e265405a34dbafa9e3dda01fb823080001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc7870104010200"
    // PSBT with one P2PKH input and one P2SH-P2WPKH input with only the first input signed, finalized, and skipped. Total input count is given but second input does not have its index.
    val invalidPSBT2 = "70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac0000000015013545e6e33b832c47050f24d3eeb93c9c03948bc716001485d13537f2e265405a34dbafa9e3dda01fb82308010401010001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc78700"

    assert(Try(PSBT.read(invalidNetworkPSBT)).isFailure)
    assert(Try(PSBT.read(missingNullTerminatorPSBT)).isFailure)
    assert(Try(PSBT.read(invalidPSBT)).isFailure)
    assert(Try(PSBT.read(invalidPSBT2)).isFailure)

  }

  it should "deserialize a PSBT" in {

    //PSBT with one P2PKH input which has a non-final scriptSig
    val firstPsbt = PSBT.read("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab30000000000")

    assert(firstPsbt.inputs.size == 1)
    assert(firstPsbt.inputs.head.nonWitnessOutput.isDefined)
    assert(firstPsbt.tx.txIn.size == 1)
    assert(!firstPsbt.tx.txIn.head.isFinal)

    //PSBT with one P2PKH input which has a non-final scriptSig and sighash type specified.
    val secondPsbt = PSBT.read("70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3000000000103040100000000")

    assert(secondPsbt.inputs.size == 1)
    assert(secondPsbt.inputs.head.sighashType.isDefined)
    assert(secondPsbt.inputs.head.nonWitnessOutput.isDefined)
    assert(secondPsbt.tx.txIn.size == 1)
    assert(!secondPsbt.tx.txIn.head.isFinal)

    //PSBT with one P2PKH input and one P2SH-P2WPKH input both with non-final scriptSigs. P2SH-P2WPKH input's redeemScript is available.
    val thirdPSBT = PSBT.read("70736274ff0100a00200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40000000000feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac0000000015013545e6e33b832c47050f24d3eeb93c9c03948bc716001485d13537f2e265405a34dbafa9e3dda01fb82308000100df0200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf6000000006a473044022070b2245123e6bf474d60c5b50c043d4c691a5d2435f09a34a7662a9dc251790a022001329ca9dacf280bdf30740ec0390422422c81cb45839457aeb76fc12edd95b3012102657d118d3357b8e0f4c2cd46db7b39f6d9c38d9a70abcb9b2de5dc8dbfe4ce31feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e13000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc78700")

    assert(thirdPSBT.inputs.size == 2)
    assert(!thirdPSBT.tx.txIn(0).hasSigScript)  //first input is P2PKH with non final script
    assert(!thirdPSBT.tx.txIn(1).hasWitness)    //second input is P2WPKH with non final script
    assert(thirdPSBT.inputs(1).witnessOutput.isDefined)

    //PSBT with one P2PKH input and one P2SH-P2WPKH input with only the first input signed and finalized.
    val fourthPSBT = PSBT.read("70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac0000000015013545e6e33b832c47050f24d3eeb93c9c03948bc716001485d13537f2e265405a34dbafa9e3dda01fb82308000001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc78700")

    assert(fourthPSBT.inputs.size == 2)
    assert(fourthPSBT.tx.txIn(0).hasSigScript)  //first input is a signed P2PKH
    assert(!fourthPSBT.tx.txIn(0).hasWitness)   //no witness data in here
    assert(!fourthPSBT.tx.txIn(1).hasSigScript) //second input is not signed/finalized
    assert(!fourthPSBT.tx.txIn(1).hasWitness)

    // PSBT with one P2PKH input and one P2SH-P2WPKH input with only the first input signed, finalized, and skipped. Input indexes are used.
    val fifthPSBT = PSBT.read("70736274ff0100fd0a010200000002ab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be4000000006a47304402204759661797c01b036b25928948686218347d89864b719e1f7fcf57d1e511658702205309eabf56aa4d8891ffd111fdf1336f3a29da866d7f8486d75546ceedaf93190121035cdc61fc7ba971c0b501a646a2a83b102cb43881217ca682dc86e2d73fa88292feffffffab0949a08c5af7c49b8212f417e2f15ab3f5c33dcf153821a8139f877a5b7be40100000000feffffff02603bea0b000000001976a914768a40bbd740cbe81d988e71de2a4d5c71396b1d88ac8e240000000000001976a9146f4620b553fa095e721b9ee0efe9fa039cca459788ac0000000015013545e6e33b832c47050f24d3eeb93c9c03948bc716001485d13537f2e265405a34dbafa9e3dda01fb82308010401010001012000e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc7870104010100")

    assert(fifthPSBT.tx.txIn.size == 2) //TX has 2 inputs
    assert(fifthPSBT.inputs.size == 2)  //Originally there is only one PSBT inputs but a new empty one must be added by the parser
    //assert(fifthPSBT.inputs(0).inputIndex == Some(0)) // FAIL!! Shouldn't we ensure the specified index is unique?
    //assert(fifthPSBT.inputs(1).inputIndex == Some(1)) // FAIL!!

    // PSBT with one P2SH-P2WSH input of a 2-of-2 multisig, redeemScript, witnessScript, and keypaths are available. Contains one signature.
    val sixthPSBT = PSBT.read("70736274ff0100550200000001279a2323a5dfb51fc45f220fa58b0fc13e1e3342792a85d7e36cd6333b5cbc390000000000ffffffff01a05aea0b000000001976a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac0000000015016345200f68d189e1adc0df1c4d16ea8f14c0dbeb220020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d56812102771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d568147522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae220303b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4610b4a6ba67000000800000008004000080220303de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd10b4a6ba67000000800000008005000080000100fd51010200000002f1d8d4b1acab9217bcbd0a09e37876efd79cf753baa2b2362e7d429c0deafbf5000000006a47304402202f29ddfff387626cf43fcae483456fb9d12d7f50fb10b39c245bab238d960d6502200f32fa3197dc6aa1fc870e33d8c590378862ce0b9bf6be865d5aac0a7390ae3a012102ead596687ca806043edc3de116cdf29d5e9257c196cd055cf698c8d02bf24e99fefffffff1d8d4b1acab9217bcbd0a09e37876efd79cf753baa2b2362e7d429c0deafbf5010000006b483045022100dc3bc94086fd7d48102a8290c737e27841bc1ce587fd4d9efe96a37d88c03a6502206dea717b8225b4ae9e1624bfc02927edac222ee094bf009996d9d0305d7645f501210394f62be9df19952c5587768aeb7698061ad2c4a25c894f47d8c162b4d7213d05feffffff01955eea0b0000000017a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87fb2e1300220203b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd4646304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a0100")

    assert(sixthPSBT.bip32Data.isDefined)
    assert(sixthPSBT.redeemScripts.nonEmpty)
    assert(sixthPSBT.witnessScripts.nonEmpty)
    assert(sixthPSBT.inputs.head.partialSigs.size == 1)

  }

  it should "serialize into PSBT format" in {

    val hexPSBT = "70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e130001040101000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3000000000104010000"
    val psbt = PSBT.read(hexPSBT)

    val out = new ByteArrayOutputStream()
    PSBT.write(psbt, out)

    val serializedPsbt = BinaryData(out.toByteArray)

    assert(Try(PSBT.read(serializedPsbt.toString)).isSuccess)
    assert(serializedPsbt.toString == hexPSBT)

  }

}