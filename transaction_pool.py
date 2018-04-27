import json

from functools import reduce
from transaction import validate_transaction


transactionPool = []

def get_transaction_pool():
    return transactionPool

def add_to_transaction_pool(tx, unspenttx_outs):
    print('adding')
    if not validate_transaction(tx, unspenttx_outs):
        print('Trying to add invalid tx to pool')

    if not is_valid_tx_for_pool(tx, transactionPool):
        print('Trying to add invalid tx to pool')

    print('adding transaction to txPool')
    transactionPool.append(tx)


def has_tx_in(txIn, unspenttx_outs):
    try:
        next(uTxO for uTxO in unspenttx_outs
                         if uTxO.tx_out_id == txIn.tx_out_id and uTxO.tx_out_index == txIn.tx_out_index)
        return True
    except StopIteration:
        return False

def update_transaction_pool(unspenttx_outs):

    global transactionPool
    for tx in transactionPool[:]:
        for txIn in tx.tx_ins:
            if not has_tx_in(txIn, unspenttx_outs):
                transactionPool.remove(tx)
                print('removing the following transactions from txPool: %s' % json.dumps(tx))
                break


def get_tx_pool_ins(aTransactionPool):
    return reduce(lambda a,b : a + b, map(lambda tx : tx.tx_ins, aTransactionPool), [])


def is_valid_tx_for_pool(tx, aTtransactionPool):
    txPoolIns = get_tx_pool_ins(aTtransactionPool)
    print('pool')
    print(tx.tx_ins)

    def contains_tx_in(txIn):
        try:
            return next(txPoolIn for txPoolIn in txPoolIns if txIn.tx_out_index == txPoolIn.tx_out_index and txIn.tx_out_id == txPoolIn.tx_out_id)
        except StopIteration:
            False


    for txIn in tx.tx_ins:
        if contains_tx_in(txIn):
            print('txIn already found in the txPool')
            return False

    return True
