from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import hashlib
import json
from time import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Configuração do Flask e SQLAlchemy
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://blockchain_user:secure_password@localhost/blockchain'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Modelos para o banco de dados
class Wallet(db.Model):
    __tablename__ = 'wallets'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(128), unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    block_id = db.Column(db.Integer, db.ForeignKey('blocks.id'), nullable=True)
    sender = db.Column(db.String(128), nullable=False)
    recipient = db.Column(db.String(128), nullable=False)
    amount = db.Column(db.Float, nullable=False)

class Block(db.Model):
    __tablename__ = 'blocks'
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.Float, nullable=False)
    proof = db.Column(db.Integer, nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)

# Classe Blockchain
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.load_chain_from_db()

    def load_chain_from_db(self):
        """Carrega os blocos existentes no banco de dados."""
        blocks = Block.query.order_by(Block.index).all()
        for block in blocks:
            self.chain.append({
                'index': block.index,
                'timestamp': block.timestamp,
                'transactions': self.load_transactions_for_block(block.id),
                'proof': block.proof,
                'previous_hash': block.previous_hash,
            })

        # Cria o bloco gênesis, caso a cadeia esteja vazia
        if not self.chain:
            self.new_block(proof=100, previous_hash='1')

    def load_transactions_for_block(self, block_id):
        transactions = Transaction.query.filter_by(block_id=block_id).all()
        return [
            {'sender': tx.sender, 'recipient': tx.recipient, 'amount': tx.amount}
            for tx in transactions
        ]

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)

        # Salvar no banco de dados
        block_record = Block(
            index=block['index'],
            timestamp=block['timestamp'],
            proof=block['proof'],
            previous_hash=block['previous_hash']
        )
        db.session.add(block_record)
        db.session.commit()

        # Atualizar ID do bloco nas transações associadas
        for tx in block['transactions']:
            transaction_record = Transaction.query.filter_by(
                sender=tx['sender'],
                recipient=tx['recipient'],
                amount=tx['amount'],
                block_id=None
            ).first()
            if transaction_record:
                transaction_record.block_id = block_record.id
                db.session.commit()

        return block

    def new_transaction(self, sender, recipient, amount):
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        # Salvar no banco de dados
        transaction = Transaction(sender=sender, recipient=recipient, amount=amount)
        db.session.add(transaction)
        db.session.commit()

        return self.last_block['index'] + 1 if self.chain else 1

    def get_balance(self, address):
        """Calcula o saldo de uma carteira."""
        balance = 0
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['sender'] == address:
                    balance -= transaction['amount']
                if transaction['recipient'] == address:
                    balance += transaction['amount']
        for transaction in self.current_transactions:
            if transaction['sender'] == address:
                balance -= transaction['amount']
            if transaction['recipient'] == address:
                balance += transaction['amount']
        return balance

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

# Funções auxiliares de chave e assinatura
def generate_wallet():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key_pem.decode('utf-8'), public_key_pem.decode('utf-8')

def sign_transaction(private_key_pem, data):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
    )
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature.hex()

def verify_signature(public_key_pem, data, signature):
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    try:
        public_key.verify(
            bytes.fromhex(signature),
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

# Instanciar o Blockchain
with app.app_context():
    db.create_all()
    blockchain = Blockchain()

# Rotas
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['sender', 'recipient', 'amount', 'signature', 'public_key']
    if not all(k in values for k in required):
        return jsonify({'error': 'Missing values'}), 400

    # Validar assinatura
    is_valid = verify_signature(
        values['public_key'],
        f"{values['sender']}{values['recipient']}{values['amount']}",
        values['signature']
    )
    if not is_valid:
        return jsonify({'error': 'Invalid signature'}), 400

    # Validar saldo
    sender_balance = blockchain.get_balance(values['sender'])
    if sender_balance < values['amount']:
        return jsonify({'error': 'Insufficient funds'}), 400

    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/wallet/balance', methods=['GET'])
def get_balance():
    address = request.args.get('address')
    if not address:
        return jsonify({'error': 'Address is required'}), 400

    balance = blockchain.get_balance(address)
    return jsonify({'address': address, 'balance': balance}), 200

@app.route('/wallet/new', methods=['GET'])
def create_wallet():
    private_key, public_key = generate_wallet()
    address = hashlib.sha256(public_key.encode()).hexdigest()

    # Salvar no banco de dados
    wallet = Wallet(address=address, public_key=public_key)
    db.session.add(wallet)
    db.session.commit()

    return jsonify({'private_key': private_key, 'public_key': public_key, 'address': address}), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

# Iniciar o servidor
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
