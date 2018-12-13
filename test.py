from nacl.public import PrivateKey, SealedBox
import nacl.encoding
from nacl.signing import SigningKey
import nacl.utils
import nacl.hash

from contexttimer import Timer

import pickle
from base64 import b64encode, b64decode


NUM_USERS = 10
DB_BITS = 256

#### utils:
def makehash(data):
    #print(data)
    data = obj2bytes(data)
    return nacl.hash.sha256(data, encoder=nacl.encoding.HexEncoder)

def obj2bytes(data):
    if type(data) is not bytes:
        data = pickle.dumps(data)
    return data

def bytes2obj(data):
    return pickle.loads(data)

def get_key_string(key):
    return key.encode(encoder=nacl.encoding.HexEncoder)

class KeyAuthority:
    def __init__(self):
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
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

        voting_group_hash = makehash(voting_group)
        
        user_token = makehash((epoch, voting_group, user_public_key_str, secret_key))
        pdp = self.signing_key.sign(obj2bytes((distance_result, voting_group_hash, user_token)))
        sdp = self.signing_key.sign(obj2bytes((user_public_key_str, pdp)))
        esdp = SealedBox(user_public_key).encrypt(sdp)
        return esdp

class DistanceVerifier:
    def __init__(self):
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

    def set_voting_group(self, group):
        self.voting_group = group

    def request_distance_verification(self, device, epoch):
        # ok! let's do distance verification
        challenge = nacl.utils.random(DB_BITS // 8)

        distance = device.distance
        response = device.handle_db_challenge(challenge)

        distance_result = self.signing_key.sign(obj2bytes((distance, epoch)))
        esdp = key_authority.complete_distance_verification(challenge, response, epoch, self.voting_group, distance_result)
        return esdp


class User:
    def __init__(self, distance):
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.db_key = nacl.utils.random(DB_BITS // 8)
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