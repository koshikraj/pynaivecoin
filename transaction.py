import binascii
import json

from Crypto.Hash import SHA256
from collections import defaultdict
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from functools import reduce

COINBASE_AMOUNT = 50


class UnspentTxOut:

    def __init__(self, tx_out_id, tx_out_index, address, amount):
        self.tx_out_id = tx_out_id
        self.tx_out_index = tx_out_index
        self.address = address
        self.amount = amount


class TxIn:
    def __init__(self, tx_out_id, tx_out_index, signature):
        self.tx_out_id = tx_out_id
        self.tx_out_index = tx_out_index
        self.signature = signature


class TxOut:
    def __init__(self, address, amount):
        self.address = address
        self.amount = amount


class Transaction:

    def __init__(self, tx_ins, tx_outs):

        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.id = get_transaction_id(self)


def get_transaction_id(transaction):

    txInContent = reduce(lambda a, b : a + b, map(
        (lambda tx_in: str(tx_in.tx_out_id) + str(tx_in.tx_out_index)), transaction.tx_ins), '')

    txOutContent = reduce(lambda a, b : a + b, map(
        (lambda tx_out: str(tx_out.address) + str(tx_out.amount)), transaction.tx_outs), '')

    return SHA256.new((txInContent + txOutContent).encode()).hexdigest()


def validate_transaction(transaction, aUnspenttx_outs):

    if not is_valid_transaction_structure(transaction):
        return False

    if get_transaction_id(transaction) != transaction.id:
        print('invalid tx id: ' + transaction.id)
        return False

    hasValidtx_ins = reduce((lambda a, b: a and b), map(lambda tx_in: validate_tx_in(tx_in, transaction, aUnspenttx_outs), transaction.tx_ins), True)


    if not hasValidtx_ins:
        print('some of the tx_ins are invalid in tx: ' + transaction.id)
        return False


    totalTxInValues = reduce((lambda a, b : a + b), map(lambda tx_in : get_tx_in_amount(tx_in, aUnspenttx_outs), transaction.tx_ins), 0)

    totalTxOutValues = reduce((lambda a, b : a + b), map(lambda tx_out : tx_out.amount, transaction.tx_outs), 0)


    if totalTxOutValues != totalTxInValues:
        print('totalTxOutValues !== totalTxInValues in tx: ' + transaction.id)
        return False

    return True


def validate_block_transactions(aTransactions, aUnspenttx_outs, blockIndex):

    coinbaseTx = aTransactions[0]
    if not validate_coinbase_tx(coinbaseTx, blockIndex):
        print('invalid coinbase transaction: ' + json.dumps(coinbaseTx))
        return False

    # check for duplicate tx_ins. Each txIn can be included only once
    tx_ins = reduce((lambda a, b : a + b), map(lambda tx : tx.tx_ins, aTransactions))

    if has_duplicates(tx_ins):
        return False

    # all but coinbase transactions
    normalTransactions = aTransactions[1:]
    return reduce((lambda a, b : a and b), map(lambda tx : validate_transaction(tx, aUnspenttx_outs), normalTransactions), True)


def has_duplicates(tx_ins):

    grouped = defaultdict(list)
    for tx_in in tx_ins:
        grouped[tx_in.tx_out_id].append(tx_in.tx_out_index)
    for key, value in grouped.items():
        if len(value) != len(set(value)):
            print('duplicate txIn: ' + key);
            return True
    return  False




def validate_coinbase_tx(transaction, blockIndex):
    if transaction is None:
        print('the first transaction in the block must be coinbase transaction');
        return False

    if get_transaction_id(transaction) != transaction.id:
        print('invalid coinbase tx id: ' + transaction.id)
        return False

    if len(transaction.tx_ins) != 1:
        print('one txIn must be specified in the coinbase transaction')
        return False

    if transaction.tx_ins[0].tx_out_index != blockIndex:
        print('the txIn signature in coinbase tx must be the block height')
        return False

    if len(transaction.tx_outs) != 1:
        print('invalid number of tx_outs in coinbase transaction')
        return False

    if transaction.tx_outs[0].amount != COINBASE_AMOUNT:
        print('invalid coinbase amount in coinbase transaction')
        return False

    return True


def validate_tx_in(txIn, transaction, aUnspenttx_outs):

    referencedUTxOut = [uTxO for uTxO in aUnspenttx_outs if uTxO.tx_out_id == txIn.tx_out_id and uTxO.tx_out_index == txIn.tx_out_index][0]
    if referencedUTxOut == []:
        print('referenced txOut not found: ' + json.dumps(txIn))
        return False

    address = referencedUTxOut.address

    vk = VerifyingKey.from_string(bytes.fromhex(address), curve=SECP256k1)

    try:
        vk.verify(bytes.fromhex(txIn.signature),transaction.id.encode())

    except Exception as e:
        # change the exception
        print('invalid txIn signature: %s txId: %s address: %s' % (txIn.signature, transaction.id, referencedUTxOut.address))
        return False

    return True


def get_tx_in_amount(txIn, aUnspenttx_outs):
    return find_unspent_tx_out(txIn.tx_out_id, txIn.tx_out_index, aUnspenttx_outs).amount


def find_unspent_tx_out(transactionId, index, aUnspenttx_outs):
    try:
        return next(uTxO for uTxO in aUnspenttx_outs if uTxO.tx_out_id == transactionId and uTxO.tx_out_index == index)
    except Exception:
        return False


def get_coinbase_transaction(address, blockIndex):

    txIn = TxIn('', blockIndex, '')
    t = Transaction([txIn], [TxOut(address, COINBASE_AMOUNT)])
    return t


def sign_tx_in(transaction, txInIndex,
               privateKey, aUnspenttx_outs):

    txIn = transaction.tx_ins[txInIndex]
    dataToSign = str(transaction.id)
    referencedUnspentTxOut = find_unspent_tx_out(txIn.tx_out_id, txIn.tx_out_index, aUnspenttx_outs)
    if referencedUnspentTxOut is None:
        print('could not find referenced txOut')
        # throw Error();

    referencedAddress = referencedUnspentTxOut.address

    if get_public_key(privateKey) != referencedAddress:
        print('trying to sign an input with private' +
              ' key that does not match the address that is referenced in txIn')
        # throw Error();

    # key = ec.keyFromPrivate(privateKey, 'hex')
    sk = SigningKey.from_string(privateKey, curve=SECP256k1)
    signature = binascii.b2a_hex(sk.sign(dataToSign.encode())).decode()
    return signature


def update_unspent_tx_outs(aTransactions, aUnspenttx_outs):

    def find_utxos(t):
        utxos = []
        for index, txOut in enumerate(t.tx_outs):
            utxos.append(UnspentTxOut(t.id, index, txOut.address, txOut.amount))
        return utxos

    newUnspenttx_outs = reduce((lambda a, b: a + b), map(lambda t: find_utxos(t), aTransactions), [])


    consumedtx_outs = list(map(lambda txin: UnspentTxOut(txin.tx_out_id, txin.tx_out_index, '', 0), reduce((lambda a, b : a + b), map(lambda t : t.tx_ins, aTransactions), [])))

    resultingUnspenttx_outs = list(filter(lambda uTxo : not find_unspent_tx_out(uTxo.tx_out_id, uTxo.tx_out_index, consumedtx_outs), aUnspenttx_outs)) + newUnspenttx_outs

    return resultingUnspenttx_outs


def processTransactions(aTransactions, aUnspenttx_outs, blockIndex):

    if not validate_block_transactions(aTransactions, aUnspenttx_outs, blockIndex):
        print('invalid block transactions')
        return None
    return update_unspent_tx_outs(aTransactions, aUnspenttx_outs)


# def toHexString = (byteArray): string => {
# return Array.from(byteArray, (byte: any) => {
# return ('0' + (byte & 0xFF).toString(16)).slice(-2);
# }).join('');
# };

def get_public_key(aPrivateKey):

    sk = SigningKey.from_string(aPrivateKey
                                , curve=SECP256k1)
    vk = sk.get_verifying_key()
    return binascii.b2a_hex(vk.to_string()).decode()


def is_valid_tx_in_structure(txIn: TxIn):
    if txIn is None:
        print('txIn is null')
        return False
    elif type(txIn.signature) is not str:
        print('invalid signature type in txIn')
        return False
    elif type(txIn.tx_out_id) is not str:
        print('invalid tx_out_id type in txIn')
        return False
    elif type(txIn.tx_out_index) is not int:
        print('invalid tx_out_index type in txIn')
        return False
    else:
        return True


def is_valid_tx_out_structure(txOut):
    if txOut is None:
        print('txOut is null')
        return False
    elif type(txOut.address) != str:
        print('invalid address type in txOut')
        return False
    elif not is_valid_address(txOut.address):
        print('invalid TxOut address')
        return False
    elif type(txOut.amount) != int:
        print('invalid amount type in txOut')
        return False
    else:
        return True


def is_valid_transaction_structure(transaction):

    if type(transaction.id) != str:
        print('transactionId missing')
        return False

    if not isinstance(transaction.tx_ins, list):
        print('invalid tx_ins type in transaction')
        return False

    if (not reduce((lambda a, b : a and b),
                   map(lambda tx_in : is_valid_tx_in_structure(tx_in), transaction.tx_ins), True)):


        return False

    if not isinstance(transaction.tx_outs, list):

        print('invalid tx_ins type in transaction')
        return False

    if (not reduce((lambda a, b : a and b),
                   map(lambda tx_out : is_valid_tx_out_structure(tx_out), transaction.tx_outs), True)):

        return False

    return True


# valid address is a valid ecdsa public key in the 04 + X-coordinate + Y-coordinate format
def is_valid_address(address):

    import re
    if len(address) != 128:
        print('invalid public key length')
        return False
    elif re.match('^[a-fA-F0-9]+$', address) is None:
        print('public key must contain only hex characters')
        return False
    # elif not address.startsWith('04'):
    #     print('public key must start with 04')
    #     return False

    return True



