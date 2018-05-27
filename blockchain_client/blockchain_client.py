'''
title           : blockchain_client.py
description     : A blockchain client implemenation, with the following features
                  - Wallets generation using Public/Private key encryption (based on RSA algorithm)
                  - Generation of transactions with RSA encryption      
author          : Adil Moujahid
date_created    : 20180212
date_modified   : 20180309
version         : 0.3
usage           : python blockchain_client.py
                  python blockchain_client.py -p 8080
                  python blockchain_client.py --port 8080
python_version  : 3.6.1
Comments        : Wallet generation and transaction signature is based on [1]
References      : [1] https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
'''

from collections import OrderedDict
from flask import Flask, jsonify, request, render_template
from ecdsa import SigningKey,VerifyingKey
import ecdsa
import binascii

class Transaction:

    def __init__(self, sender_address, sender_private_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

    def sign_transaction(self):
        """
        Sign transaction with private key   
        """
        sk = SigningKey.from_pem(open("private.pem").read())
        message = str(self.to_dict()).encode('utf-8')
        sig = sk.sign(message)
        return binascii.hexlify(sig).decode('utf-8')       
        
app = Flask(__name__)

@app.route('/')
def index():
	return render_template('./index.html')

@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')

@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
 
    sk = SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    
    open("private.pem","wb").write(sk.to_pem())
    open("public.pem" ,"wb").write(vk.to_pem()) 
    
    ssk=sk.to_string() 
    svk=vk.to_string() 
    
    print(ssk)
    print(svk)

    fsk = SigningKey.from_pem(sk.to_pem())
    fvk = VerifyingKey.from_pem(vk.to_pem())
    
    print(fsk)
    print(fvk)
    
    fpemsk = SigningKey.from_pem(open("private.pem").read())
    print(fpemsk.to_string())
    
    fpemvk = VerifyingKey.from_pem(open("public.pem").read())
    print(fpemvk.to_string())
        
    response = {  
        'private_key': binascii.hexlify(ssk).decode('utf-8'),
        'public_key' : binascii.hexlify(svk).decode('utf-8')     
    }
    
    return jsonify(response), 200

@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
	
	sender_address = request.form['sender_address']
	sender_private_key = request.form['sender_private_key']
	recipient_address = request.form['recipient_address']
	value = request.form['amount']

	transaction = Transaction(sender_address, sender_private_key, recipient_address, value)

	response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

	return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)