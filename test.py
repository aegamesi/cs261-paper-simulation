from Cryptodome.PublicKey import RSA, ECC
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Signature import DSS

from contexttimer import Timer

import json
from base64 import b64encode, b64decode


NUM_USERS = 2
RSA_BITS = 2048
DB_BITS = 256

#### utils:
def generate_ecc_key():
    """
    Returns (public key, secret key)
    """
    ecc_key = ECC.generate(curve='P-256')
    return ecc_key.public_key(), ecc_key

def generate_rsa_key():
    rsa_key = RSA.generate(2048)
    return rsa_key.publickey(), rsa_key

def makehash(data):
    print(data)
    if type(data) is not bytes:
        data = json.dumps(data).encode('utf-8')
    return SHA256.new(data)

def sign(key, data):
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(makehash(data))
    signature = b64encode(signature).decode('utf-8')
    return signature, data

def verify_signature(key, data):
    signature, contents = data
    signature = b64decode(signature)
    verifier = DSS.new(key, 'fips-186-3')
    verifier.verify(makehash(data), signature)

def get_key_string(key):
    return key.export_key(format='PEM')

def public_encrypt(key, data):
    if type(data) is not bytes:
        data = json.dumps(data).encode('utf-8')

    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    output = (enc_session_key, cipher_aes.nonce, tag, ciphertext)
    return output

def public_decrypt(key, data, decode_json=True):
    enc_session_key, nonce, tag, ciphertext = data

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    if decode_json:
        return json.loads(data.decode("utf-8"))
    return data

class KeyAuthority:
    def __init__(self):
        self.public_key, self.secret_key = generate_ecc_key()
        # self.pk_to_db = {}
        self.db_to_pk = {}

    def make_device(self, distance):
        user = User(distance)
        # self.pk_to_db[user.public_key_str] = user.db_key
        self.db_to_pk[user.db_key] = user.public_key
        return user

    def complete_distance_verification(self, db_challenge, db_response, epoch, voting_group, distance_result):
        # derive secret key from db_challenge/db_response
        secret_key = db_response  # TODO not quite right but ok

        user_public_key = self.db_to_pk.get(secret_key)
        if user_public_key is None:
            raise Exception('KeyAuthority: could not find DB Key -> PK mapping')

        user_public_key_str = get_key_string(user_public_key)
        if user_public_key_str not in voting_group:
            raise Exception('KeyAuthority: user PK not in voting group')

        voting_group_hash = makehash(voting_group).hexdigest()
        
        user_token = makehash((epoch, voting_group, user_public_key_str, secret_key)).hexdigest()
        pdp = sign(self.secret_key, (distance_result, voting_group_hash, user_token))
        sdp = sign(self.secret_key, (user_public_key_str, pdp))
        esdp = public_encrypt(user_public_key, sdp)
        return esdp

class DistanceVerifier:
    def __init__(self):
        self.public_key, self.secret_key = generate_ecc_key()

    def set_voting_group(self, group):
        self.voting_group = group

    def request_distance_verification(self, device, epoch):
        # ok! let's do distance verification
        challenge = get_random_bytes(DB_BITS // 8)

        distance = device.distance
        response = device.handle_db_challenge(challenge)

        distance_result = sign(self.secret_key, (distance, epoch))
        esdp = key_authority.complete_distance_verification(challenge, response, epoch, self.voting_group, distance_result)
        return esdp


class User:
    def __init__(self, distance):
        self.public_key, self.secret_key = generate_rsa_key()
        self.db_key = b64encode(get_random_bytes(DB_BITS // 8)).decode('utf-8')
        self.public_key_str = get_key_string(self.public_key)
        self.distance = distance

    def handle_db_challenge(self, challenge):
        # TODO: this is not actually how this works -- should have a keyed random function,
        # 2 registers, use challenge as bit select, etc. buuut....
        return self.db_key

    def set_voting_group(self, group):
        self.voting_group = group

    def do_distance_verification(self):
        esdp = distance_verifier.request_distance_verification(self, epoch)
        print(len(esdp))
        print(esdp)

#####################

key_authority = KeyAuthority()
distance_verifier = DistanceVerifier()

# Generate Devices
users = []
with Timer() as t:
    for i in range(NUM_USERS):
        user = key_authority.make_device(100.0)
        users.append(user)
print("created {} devices in {}".format(len(users), t.elapsed))

# set parameters
max_distance = 500.0
epoch = 1234
voting_group = sorted([user.public_key_str for user in users])

distance_verifier.set_voting_group(voting_group)
for user in users:
    user.set_voting_group(voting_group)

# go!
with Timer() as t:
    users[0].do_distance_verification()
print("did {} distance verification in {}".format(len(users), t.elapsed))