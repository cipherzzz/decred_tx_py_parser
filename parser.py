from binascii import hexlify, unhexlify
from struct import pack, Struct

unpack_int32_from = Struct('<i').unpack_from
unpack_int64_from = Struct('<q').unpack_from
unpack_uint16_from = Struct('<H').unpack_from
unpack_uint32_from = Struct('<I').unpack_from
unpack_uint64_from = Struct('<Q').unpack_from

class DecredTxParser(object):
    '''Deserializes blocks into transactions.

    External entry points are read_tx(), read_tx_and_hash(),
    read_tx_and_vsize() and read_block().

    This code is performance sensitive as it is executed 100s of
    millions of times during sync.
    '''

    def __init__(self, hex, start=0):

        print('Hex TX')
        print(hex)
        print('')
        print('')

        binary = unhexlify(hex)
        assert isinstance(binary, bytes)

        print('Binary TX')
        print(binary)
        print('')
        print('')

        self.binary = binary
        self.binary_length = len(binary)
        self.cursor = start

    def read_tx(self):
        version = self._read_le_uint16()
        txType = self._read_le_uint16()
        print('***TX Details')
        print('version: '+ str(version))
        print('txType: '+ str(txType))
        print('')

        if txType != 2 and txType != 3 and txType != 4:
            self._read_input(txType)  
            self._read_output()

            lock_time = self._read_le_uint32() #tx root
            expiry = self._read_le_uint32() #tx root
            print('lock_time: '+ str(lock_time))
            print('expiry: '+ str(expiry))
            print('')

        self._read_witness(txType)


    def _read_witness(self, txType):
        #Parse Witness
        if txType == 0 or txType == 2:
            num_witness = self._read_varint()  
            print('# of witness: '+ str(num_witness))
            for j in range(num_witness):
                value = self._read_le_int64()        #witness
                blockHeight = self._read_le_uint32() #witness
                blockIndex = self._read_le_uint32()  #witness
                script_length = self._read_varint()
                script = self._read_nbytes(script_length) #witness
                print('value: '+ str(value))
                print('blockHeight: '+ str(blockHeight))
                print('blockIndex: '+ str(blockIndex))
                print('script_length: '+ str(script_length))
                print('script: '+ str(script))
        if txType == 3:
            num_witness = self._read_varint()  
            print('# of witness: '+ str(num_witness))
            for j in range(num_witness):
                script_length = self._read_varint()
                script = self._read_nbytes(script_length) #witness
                print('script_length: '+ str(script_length))
                print('script: '+ str(script)) 
        if txType == 4:
            num_witness = self._read_varint()  
            print('# of witness: '+ str(num_witness))
            for j in range(num_witness):
                value = self._read_le_int64()        #witness
                script_length = self._read_varint()
                script = self._read_nbytes(script_length) #witness
                print('value: '+ str(value))
                print('script_length: '+ str(script_length))
                print('script: '+ str(script))               


    def _read_input(self, txType):
        #Parse Inputs
        num_inputs = self._read_varint()
        print('# of inputs: '+ str(num_inputs))
        for i in range(num_inputs):
            print('Input '+str(i))
            #defaults
            prev_hash = 1
            prev_idx = 1
            tree = 1
            sequence = 1
            value = 0
            blockHeight = -1
            blockIndex = -1
            script = 0

            #full prefix + witness
            if txType == 0:
                prev_hash = self._read_nbytes(32) #non-witness
                prev_idx = self._read_le_uint32() #non-witness
                tree = self.read_int8()           #non-witness
                sequence = self._read_le_uint32() #non-witness
                print('prev_hash: '+ bytes(prev_hash).hex())
                print('prev_idx: '+ str(prev_idx))
                print('tree: '+ str(tree))
                print('sequence: '+ str(sequence))
            #only prefix    
            if txType == 1:
                prev_hash = self._read_nbytes(32) #non-witness
                prev_idx = self._read_le_uint32() #non-witness
                tree = self.read_int8()           #non-witness
                sequence = self._read_le_uint32() #non-witness
                print('prev_hash: '+ bytes(prev_hash).hex())
                print('prev_idx: '+ str(prev_idx))
                print('tree: '+ str(tree))
                print('sequence: '+ str(sequence))   
            #subset of witness - value + script      
            if txType == 3:
                script_length = self._read_varint()
                script = self._read_nbytes(script_length) #witness   
                print('script_length: '+ str(script_length))
                print('script: '+ str(script))       
            #subset of witness - value + script      
            if txType == 4:
                value = self._read_le_int64()        #witness 
                script_length = self._read_varint()
                script = self._read_nbytes(script_length) #witness   
                print('value: '+ str(value))
                print('script_length: '+ str(script_length))
                print('script: '+ str(script))

        print('')

    
    def _read_output(self):
        #Parse Outputs
        num_outputs = self._read_varint()    
        print('# of outputs: '+ str(num_outputs))
        for i in range(num_outputs):
            value = self._read_le_int64()
            version = self._read_le_uint16()
            script_length = self._read_varint()
            script = self._read_nbytes(script_length)
            print('Output '+str(i))
            print('value: '+ str(value))
            print('version: '+ str(version))
            print('script_length: '+ str(script_length))
            print('script: '+ str(script))
            print('')

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