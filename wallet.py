import binascii
import os
import json

from ecdsa import SigningKey, SECP256k1
from functools import reduce

from transaction import Transaction, TxOut, TxIn, get_public_key, get_transaction_id, sign_tx_in


try:
    privateKeyLocation = os.environ['PRIVATE_KEY']
except KeyError as e:
    privateKeyLocation = 'node/wallet/private_key'


def get_private_from_wallet():

    # sk = SigningKey.from_string(binascii.a2b_hex(open(privateKeyLocation).read()), curve=SECP256k1)

    return binascii.a2b_hex(open(privateKeyLocation).read())


def get_public_from_wallet():
    sk = SigningKey.from_string(get_private_from_wallet(), curve=SECP256k1)
    vk = sk.get_verifying_key()
    return binascii.b2a_hex(vk.to_string()).decode()


def generate_private_key():

    sk = SigningKey.generate(curve=SECP256k1)
    with open(privateKeyLocation, 'wt') as file_obj:
        file_obj.write(binascii.b2a_hex(sk.to_string()).decode())


def init_wallet():

    # let's not override existing private keys
    if os.path.isfile(privateKeyLocation):
        return

    generate_private_key()
    print('new wallet with private key created at : %s' % privateKeyLocation)

def delete_wallet():
    if os.path.isfile(privateKeyLocation):
        os.remove(privateKeyLocation)


def get_balance(address, unspenttx_outs):

    return sum(map(lambda utxo : utxo.amount, find_unspent_tx_outs(address, unspenttx_outs)))


def find_unspent_tx_outs(ownerAddress, unspenttx_outs):

    return list(filter(lambda utxo : utxo.address == ownerAddress, unspenttx_outs))


def find_tx_outs_for_amount(amount, myUnspenttx_outs):
    currentAmount = 0
    includedUnspenttx_outs = []
    for myUnspentTxOut in myUnspenttx_outs:
        includedUnspenttx_outs.append(myUnspentTxOut)
        currentAmount = currentAmount + myUnspentTxOut.amount
        if currentAmount >= amount:
            leftOverAmount = currentAmount - amount
            return includedUnspenttx_outs, leftOverAmount

    eMsg = 'Cannot create transaction from the available unspent transaction outputs.' + \
             ' Required amount:' + str(amount) + '. Available unspenttx_outs:' + json.dumps(myUnspenttx_outs)
    print(eMsg)
    return None, None


def create_tx_outs(receiverAddress, myAddress, amount, leftOverAmount):
    txOut1 = TxOut(receiverAddress, amount)
    if leftOverAmount == 0:
        return [txOut1]
    else:
        leftOverTx = TxOut(myAddress, leftOverAmount)
        return [txOut1, leftOverTx]


def filter_tx_pool_txs(unspenttx_outs, transactionPool):
    tx_ins = reduce((lambda a, b: a + b), map(lambda tx: tx.tx_ins, transactionPool), [])

    for unspentTxOut in unspenttx_outs[:]:
        try:
            txIn = next(aTxIn for aTxIn in tx_ins if aTxIn.tx_out_index == unspentTxOut.tx_out_index and aTxIn.tx_out_id == unspentTxOut.tx_out_id)
            unspenttx_outs.remove(unspentTxOut)
        except StopIteration as e:
            pass

    return unspenttx_outs

def create_transaction(receiverAddress, amount, privateKey,
                       unspenttx_outs, txPool):

    print('txPool has %d transactions', len(txPool))

    myAddress = get_public_key(privateKey)

    myUnspenttx_outsA = list(filter(lambda utxo: utxo.address == myAddress, unspenttx_outs))

    myUnspenttx_outs = filter_tx_pool_txs(myUnspenttx_outsA, txPool)

    # filter from unspentOutputs such inputs that are referenced in pool
    includedUnspenttx_outs, leftOverAmount = find_tx_outs_for_amount(amount, myUnspenttx_outs)
    if not includedUnspenttx_outs:
        return None

    def to_unsigned_tx_in(unspentTxOut):

        txIn = TxIn(unspentTxOut.tx_out_id, unspentTxOut.tx_out_index, '')
        return txIn

    unsignedtx_ins = list(map(to_unsigned_tx_in, includedUnspenttx_outs))

    tx = Transaction(unsignedtx_ins,
                     create_tx_outs(receiverAddress, myAddress, amount, leftOverAmount))

    def sign_transaction(tx, index):
        tx.tx_ins[index].signature = sign_tx_in(tx, index, privateKey, unspenttx_outs)

    for index, txIn in enumerate(tx.tx_ins):
        sign_transaction(tx, index)

    return tx
