# decred_tx_py_parser
An example decred transaction parser in python

## Example
* Add the hex encoded transaction to the ```test.py``` file.

Ex:
```
txHex = '0100000001d...'
deserializer = DecredTxParser(txHex, 0)
deserializer.read_tx()
```


* Run the following in the project dir
```
python3 ./test.py
```