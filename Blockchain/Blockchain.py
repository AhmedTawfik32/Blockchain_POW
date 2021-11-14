import binascii
import hashlib
import json
from collections import OrderedDict
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

MINING_SENDER = "Blockchain Winner"
MINING_REWARD = 1
MINING_DIFFICULTY = 3


class BlockChain:
    def __init__(self):
        self.transaction = []
        self.chain = []
        self.node_id = str(uuid4()).replace('-', '')
        self.nodes = set()

    @staticmethod
    def hash(last_block):
        json_string = json.dumps(last_block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(json_string)
        return h.hexdigest()

    def register_node(self, node_url):
        parsed_url = urlparse(node_url)

        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Error in Node URL')

    def resolve_conflicts(self, other_nodes):
        neighbors = other_nodes
        max_length = len(self.chain)
        new_chain = None

        for node in neighbors:
            response = requests.get('http://' + node + '/chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.verify_chain(chain):
                    max_length = length
                    new_chain = chain

            if new_chain is not None:
                self.chain = new_chain
                return True
        return False

    @staticmethod
    def valid_proof(nonce, last_hash, transactions, difficulty=MINING_DIFFICULTY):
        total_str = (str(nonce) + str(last_hash) + str(transactions)).encode('utf8')
        h = hashlib.new('sha256')
        h.update(total_str)
        hex_hash = h.hexdigest()
        return hex_hash[:MINING_DIFFICULTY] == '0' * MINING_DIFFICULTY

    def verify_chain(self, chain):
        current_block_index = 1
        last_block = chain[0]

        while current_block_index < len(chain):
            block = chain[current_block_index]

            if self.hash(last_block) != block['previous_hash']:
                return False

            transactions = block['transactions'][:-1]
            transactions_elements = ['sender_public_key', 'recipient_public_key', 'amount']
            transactions = [OrderedDict((k, transaction[k]) for k in transactions_elements) for transaction in
                            transactions]

            if not self.valid_proof(block['nonce'], block['previous_hash'], transactions, MINING_DIFFICULTY):
                return False

            current_block_index += 1
            last_block = block

        return True

    def proof_of_work(self):
        nonce = 0

        if len(self.chain) == 0:
            last_hash = '0' * 64
        else:
            last_hash = self.hash(self.chain[-1])

        while (self.valid_proof(nonce, last_hash, self.transaction)) is False:
            nonce += 1

        return nonce

    @staticmethod
    def verify_signature(confirmation_sender_public_key, confirmation_signature, transaction):
        public_key = RSA.import_key(binascii.unhexlify(confirmation_sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(confirmation_signature))
            return True
        except ValueError:
            return False

    def submit_transaction(self, confirmation_sender_public_key, confirmation_recipient_public_key,
                           confirmation_amount,
                           confirmation_signature):

        transaction = OrderedDict({
            'sender_public_key': confirmation_sender_public_key,
            'recipient_public_key': confirmation_recipient_public_key,
            'amount': confirmation_amount
        })

        # todo reward winning Node
        if confirmation_sender_public_key == MINING_SENDER:
            self.transaction.append(transaction)
            return len(self.chain) + 1
        else:
            # todo: validate signature
            is_signature_valid = self.verify_signature(confirmation_sender_public_key, confirmation_signature,
                                                       transaction)
            if is_signature_valid:
                self.transaction.append(transaction)
                return len(self.chain) + 1
            else:
                return False

    def create_block(self, nonce, previous_hash):
        block = {
            'block_number': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.transaction,
            'nonce': nonce,
            'previous_hash': previous_hash
        }
        self.transaction = []
        self.chain.append(block)
        return block


blockchain = BlockChain()

# Instance of Node
app = Flask(__name__)
CORS(app)


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/node/configure')
def configure_node():
    return render_template('./configure_blockchain.html')


@app.route('/nodes/resolve', methods=['Get'])
def resolve_nodes():
    if blockchain.resolve_conflicts(blockchain.nodes):
        return 'No conflicts', 200
    else:
        return 'There are conflicts', 400


@app.route('/nodes/get', methods=['Get'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_node():
    values = request.form.get('node_url_txt')
    nodes_url = str(values).replace(' ', '').split(',')

    if nodes_url is None:
        return 'Error: please apply a valid nodes', 400

    for node_url in nodes_url:
        blockchain.register_node(node_url)

    response = {
        'message': 'The nodes are added successfully',
        'total_nodes': [node for node in blockchain.nodes]
    }
    return jsonify(response), 200


@app.route('/chain', methods=['Get'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


@app.route('/mine', methods=['Get'])
def mine():
    # we run the proof of work algorithm
    nonce = blockchain.proof_of_work()

    blockchain.submit_transaction(confirmation_sender_public_key=MINING_SENDER,
                                  confirmation_recipient_public_key=blockchain.node_id,
                                  confirmation_amount=MINING_REWARD,
                                  confirmation_signature='')

    if len(blockchain.chain) == 0:
        previous_hash = '0' * 64
    else:
        last_block = blockchain.chain[-1]
        previous_hash = blockchain.hash(last_block)

    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': 'New Block created successfully',
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash']
    }

    return jsonify(response), 200


@app.route('/transaction/get', methods=['Get'])
def get_transaction():
    transactions = blockchain.transaction
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/transaction/new', methods=['POST'])
def new_transaction():
    requireds = ['confirmation_sender_public_key', 'confirmation_recipient_public_key', 'confirmation_amount',
                 'confirmation_signature']

    # todo check required fields
    if not all(k in request.form for k in requireds):
        return "Invalid fields or not filled", 400

    validation_result = blockchain.submit_transaction(request.form['confirmation_sender_public_key'],
                                                      request.form['confirmation_recipient_public_key'],
                                                      request.form['confirmation_amount'],
                                                      request.form['confirmation_signature'])

    if validation_result:
        response = {
            "message": "The transaction is successfully added to block number " + str(validation_result)
        }
        return jsonify(response), 201
    else:
        response = {
            "message": "The transaction is Invalid"
        }
        return jsonify(response), 406


if __name__ == '__main__':
    from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('-p', '--port', default=5001, type=int, help="Port to listen to")
args = parser.parse_args()
port = args.port
app.run(host='127.0.0.1', port=port, debug=True)
