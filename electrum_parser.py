from binascii import hexlify, unhexlify
from struct import pack, Struct
from collections import namedtuple

unpack_int32_from = Struct('<i').unpack_from
unpack_int64_from = Struct('<q').unpack_from
unpack_uint16_from = Struct('<H').unpack_from
unpack_uint32_from = Struct('<I').unpack_from
unpack_uint64_from = Struct('<Q').unpack_from

# Method decorator.  To be used for calculations that will always
# deliver the same result.  The method cannot take any arguments
# and should be accessed as an attribute.
class cachedproperty(object):

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, type):
        obj = obj or type
        value = self.f(obj)
        setattr(obj, self.f.__name__, value)
        return value

class TxDecred(namedtuple("Tx", "version inputs outputs "
                          "lock_time expiry witnesses")):
    '''Class representing a Decred transaction.'''    

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase

    def __str__(self):
        return ("Tx(version={}, inputs={}, outputs={}, lock_time={}, expiry={}, witnesses={})"
                .format(self.version, self.inputs, self.outputs, self.lock_time, self.expiry, self.witnesses))    

class TxDecredInput(namedtuple("TxDecredInput", "prev_hash prev_idx tree sequence")):
    '''Class representing a decred transaction input.'''

    ZERO = bytes(32)
    MINUS_1 = 4294967295

    @cachedproperty
    def is_coinbase(self):
        return (self.prev_hash == TxInput.ZERO and
                self.prev_idx == TxInput.MINUS_1)

    def __str__(self):
        prev_hash = hash_to_str(self.prev_hash)
        return ("Input(prev_hash={}, prev_idx={}, tree={}, sequence={})"
                .format(prev_hash, self.prev_idx, self.tree, self.sequence))        
                

class TxDecredOutput(namedtuple("TxDecredOutput", "value version script")):
    
    def __str__(self):
        script = self.script.hex()
        return ("Output(value={}, version={}, script={})"
                .format(self.value, self.version, self.script))

class TxDecredWitness(namedtuple("TxDecredWitness", "value blockHeight blockIndex script")):
    def __str__(self):
        script = self.script.hex()
        return ("Witness(value={}, blockHeight={}, blockIndex={}, script={})"
                .format(self.value, self.blockHeight, self.blockIndex, script))    

class DecredTxParser(object):
    '''Deserializes blocks into transactions.

    External entry points are read_tx(), read_tx_and_hash(),
    read_tx_and_vsize() and read_block().

    This code is performance sensitive as it is executed 100s of
    millions of times during sync.
    '''

    def __init__(self, hex, start=0):

        binary = unhexlify(hex)
        assert isinstance(binary, bytes)

        self.binary = binary
        self.binary_length = len(binary)
        self.cursor = start

    def read_tx(self):
        version = self._read_le_uint16()
        txType = self._read_le_uint16()
        inputs = ''
        outputs = ''
        lock_time = ''
        expiry = ''
        witnesses = '' 

        if txType == 0 or txType == 1:
            inputs = self._read_inputs()  
            outputs = self._read_outputs()
            lock_time = self._read_le_uint32()
            expiry = self._read_le_uint32()

        if txType != 1:    
            witnesses = self._read_witnesses(txType)

        return TxDecred(
            version,
            inputs,
            outputs,
            lock_time,
            expiry,
            witnesses
        )    


    def _read_witnesses(self, txType):
        read_witness = self._read_witness
        return [read_witness(txType) for i in range(self._read_varint())]

    def _read_witness(self, txType):

        value = ''
        blockHeight = ''
        blockIndex = ''
        script = ''

        if txType == 0 or txType == 2: 
            value = self._read_le_int64()
            blockHeight = self._read_le_uint32()
            blockIndex = self._read_le_uint32()
            script = self._read_nbytes(self._read_varint())
        if txType == 3:
            script = self._read_nbytes(self._read_varint())
        if txType == 4:
            value = self._read_le_int64()
            script = self._read_nbytes(self._read_varint())

        return TxDecredWitness(
            value,
            blockHeight,
            blockIndex,
            script
        )

    def _read_inputs(self):
        read_input = self._read_input
        return [read_input() for i in range(self._read_varint())]

    def _read_input(self):
        return TxDecredInput(
            self._read_nbytes(32),  #prev_hash
            self._read_le_uint32(), #prev_idx
            self.read_int8(),       #tree
            self._read_le_uint32() #sequence
        )
    
    def _read_outputs(self):
        read_output = self._read_output
        return [read_output() for i in range(self._read_varint())]

    def _read_output(self):
        return TxDecredOutput(
            self._read_le_int64(),                   #value
            self._read_le_uint16(),                  #version
            self._read_nbytes(self._read_varint()),  #script
        )

    def _read_byte(self):
        cursor = self.cursor
        self.cursor += 1
        return self.binary[cursor]

    def _read_nbytes(self, n):
        cursor = self.cursor
        self.cursor = end = cursor + n
        assert self.binary_length >= end
        return self.binary[cursor:end]

    def _read_varbytes(self):
        return self._read_nbytes(self._read_varint())

    def _read_varint(self):
        n = self.binary[self.cursor]
        self.cursor += 1
        if n < 253:
            return n
        if n == 253:
            return self._read_le_uint16()
        if n == 254:
            return self._read_le_uint32()
        return self._read_le_uint64()

    def _read_le_int32(self):
        result, = unpack_int32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_int64(self):
        result, = unpack_int64_from(self.binary, self.cursor)
        self.cursor += 8
        return result

    def _read_le_uint16(self):
        result, = unpack_uint16_from(self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_le_uint32(self):
        result, = unpack_uint32_from(self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_uint64(self):
        result, = unpack_uint64_from(self.binary, self.cursor)
        self.cursor += 8
        return result

    def read_int8(self):
        n = self.binary[self.cursor]
        self.cursor += 1
        return n    