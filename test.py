from electrum_parser import DecredTxParser

#TestTxSerialize - Type 0 - Full Serialization
txHex = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0200f2052a01000000abab434104d64bdfd09eb1c5fe295abdeb1dca4281be988e2da0b6c1c6a59dc226c28624e18175e851c96b973d81b01cc31f047834bc06d6d6edf620d184241a6aed8b63a6ac00e1f50500000000bcbc434104d64bdfd09eb1c5fe295abdeb1dca4281be988e2da0b6c1c6a59dc226c28624e18175e851c96b973d81b01cc31f047834bc06d6d6edf620d184241a6aed8b63a6ac00000000000000000112121212121212121515151534343434070431dc001b0162'
deserializer = DecredTxParser(txHex, 0)
tx = deserializer.read_tx()
print(tx)

#TestTxSerializePrefix - Type 1 - No Witness
txHex = '01000100010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0200f2052a01000000abab434104d64bdfd09eb1c5fe295abdeb1dca4281be988e2da0b6c1c6a59dc226c28624e18175e851c96b973d81b01cc31f047834bc06d6d6edf620d184241a6aed8b63a6ac00e1f50500000000bcbc434104d64bdfd09eb1c5fe295abdeb1dca4281be988e2da0b6c1c6a59dc226c28624e18175e851c96b973d81b01cc31f047834bc06d6d6edf620d184241a6aed8b63a6ac0000000000000000'
deserializer = DecredTxParser(txHex, 0)
tx = deserializer.read_tx()
print(tx)

#TestTxSerializeWitness - Type 2 - Only Witness
txHex = '010002000112121212121212121515151534343434070431dc001b0162'
deserializer = DecredTxParser(txHex, 0)
tx = deserializer.read_tx()
print(tx)

#TestTxSerializeWitnessSigning - Type 3 - Witness signing
txHex = '0100030001070431dc001b0162'
deserializer = DecredTxParser(txHex, 0)
tx = deserializer.read_tx()
print(tx)

#TestTxSerializeWitnessValueSigning - Type 4 - Witness value signing
txHex = '01000400011212121212121212070431dc001b0162'
deserializer = DecredTxParser(txHex, 0)
tx = deserializer.read_tx()
print(tx)