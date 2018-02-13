'''
title           : blockchain.py
description     :
author          : Adil Moujahid
date_created    : 20180212
date_modified   : 20180212
version         : 0.3
usage           : python blockchain.py
                  python blockchain.py -p 5000
                  python blockchain.py --port 5000
python_version  : 3.6.1
License         : MIT License
References      : https://github.com/dvf/blockchain/blob/master/blockchain.py
                  https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
                  https://github.com/blockchain-academy/how-build-your-own-blockchain/tree/master/src
'''

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2

class Wallet:
    """
    A wallet is a private/public key pair
    """
    def __init__(self):
        random_gen = Crypto.Random.new().read
        self._private_key = RSA.generate(1024, random_gen)
        self._public_key = self._private_key.publickey()
        self._signer = PKCS1_v1_5.new(self._private_key)
        
    @property
    def address(self):
        """We take a shortcut and say address is public key"""
        return binascii.hexlify(self._public_key.exportKey(format='DER')).decode('ascii')
    
    def sign(self, message):
        """
        Sign a message with this wallet
        """
        h = SHA.new(message.encode('utf8'))
        return binascii.hexlify(self._signer.sign(h)).decode('ascii')

class Transaction:

    def __init__(self, sender_address, recipient_address, value):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return {'sender_address': self.sender_address,
                'recipient_address': self.recipient_address,
                'value': self.value}


class Block:

    def __init__(self, block_number, timestamp, transactions,  nonce, previous_hash):
        self.block_number = block_number
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.previous_hash = previous_hash


    def __getattr__(self, attr):
        return self.data[attr]


    def to_dict(self):
        """
        Returns a python dict with block information
        """

        block = {'block_number': self.block_number,
                'timestamp': self.timestamp,
                'transactions': self.transactions,
                'nonce': self.nonce,
                'previous_hash': self.previous_hash}
        return block

    def hash(self):
        """
        Creates a SHA-256 hash of a Block
        """

        block = self.to_dict()

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()


class Node:

    def __init__(self, node_id, node_url):
        self.node_id = node_id
        self.node_url = node_url

    def __getattr__(self, attr):
        return self.data[attr]

    def to_string(self):
        return str(self.node_id) + ':' + str(self.node_url)


class Blockchain:

    def __init__(self):
        
        self.transactions = []
        self.chain = []
        self.nodes = set()
        #Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        #Create genesis block
        self.create_block(0, '00')

    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        #Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            node = Node(self.node_id, parsed_url.netloc)
            self.nodes.add(node)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            node = Node(self.node_id, parsed_url.path)
            self.nodes.add(node)
        else:
            raise ValueError('Invalid URL')


    def submit_transaction(self, sender_address, recipient_address, value):
        """
        Description
        """

        sender_address = sender_address
        recipient_address = recipient_address
        value = value

        transaction = Transaction(sender_address, recipient_address, value)
        self.transactions.append(transaction.to_dict())

        return len(self.chain) + 1



    def create_block(self, nonce, previous_hash):
        """
        Description
        """

        block = {'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': self.transactions,
                'nonce': nonce,
                'previous_hash': previous_hash}


        # Reset the current list of transactions
        self.transactions = []

        self.chain.append(block)
        return block


    def hash(self, block):
        """
        Creates a SHA-256 hash of a Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self):
        """
        Description
        """

        last_block = self.chain[-1]
        last_nonce = last_block['nonce']
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(last_nonce, nonce, last_hash) is False:
            nonce += 1

        return nonce


    def valid_proof(self, last_nonce, nonce, last_hash, difficulty=MINING_DIFFICULTY):
        """
        Description
        """

        guess = (str(last_nonce)+str(nonce)+last_hash).encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == '0'*difficulty


    def valid_chain(self, chain):
        """
        Description
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(last_block)
            print(block)
            print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['nonce'], block['nonce'], block['previous_hash']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print('http://' + node.node_url + '/chain')
            response = requests.get('http://' + node.node_url + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

# Instantiate the Node
app = Flask(__name__)

# Instantiate the Blockchain
blockchain = Blockchain()


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    nonce = blockchain.proof_of_work()

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.submit_transaction(sender_address=MINING_SENDER, recipient_address=blockchain.node_id, value=MINING_REWARD)

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender_address', 'recipient_address', 'value']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.submit_transaction(values['sender_address'], values['recipient_address'], values['value'])

    response = {'message': 'Transaction will be added to Block '+ str(index)}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node.to_string() for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200



if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)







