from nacl.public import PrivateKey, SealedBox
import nacl.encoding
from nacl.signing import SigningKey, SignedMessage
import nacl.utils
import nacl.hash
from nacl.hash import blake2b
import nacl.bindings

from contexttimer import Timer

import pickle
from base64 import b64encode, b64decode


NUM_USERS = 10000
DB_BITS = 256

#### utils:
def validate_pdp(pdp, good_voting_group_hash):
    # validates a PDP, returns the user token
    key_authority.verify_key.verify(pdp)
    distance_result, voting_group_hash, user_token = bytes2obj(pdp.message)
    distance_result = to_signed_message(distance_result)

    distance_verifier.verify_key.verify(distance_result)
    distance, e = bytes2obj(distance_result.message)

    assert e == epoch
    assert voting_group_hash == good_voting_group_hash
    assert distance < max_distance
    return user_token

def tally_votes():
    tally = {}

    for token, (commitment_key, vote) in vote_tallier.unsealed_votes.items():
        commitment = blake2b(obj2bytes(vote), key=commitment_key)

        ledger_commitment = vote_tallier.sealed_votes[token][0]
        assert ledger_commitment == commitment

        tally[vote] = tally.get(vote, 0) + 1

    return tally

########
def to_signed_message(raw_signed):
    encoder = nacl.encoding.RawEncoder
    crypto_sign_BYTES = nacl.bindings.crypto_sign_BYTES
    signature = encoder.encode(raw_signed[:crypto_sign_BYTES])
    message = encoder.encode(raw_signed[crypto_sign_BYTES:])
    signed = encoder.encode(raw_signed)

    return SignedMessage._from_parts(signature, message, signed)

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

class VoteTallier:
    def __init__(self):
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

        self.sealed_votes = {}  # user token -> sealed_vote
        self.unsealed_votes = {}  # user token -> vote

    def set_voting_group(self, group):
        self.voting_group = group
        self.voting_group_hash = makehash(voting_group)

    def do_sealed_vote(self, sealed_vote):
        user_token = validate_pdp(sealed_vote[2], self.voting_group_hash)
        receipt = self.signing_key.sign(obj2bytes(sealed_vote))
        self.sealed_votes[user_token] = sealed_vote
        return receipt

    def do_unseal_vote(self, commitment_key, vote):
        commitment = blake2b(obj2bytes(vote), key=commitment_key)

        for token, sealed_vote in self.sealed_votes.items():
            if sealed_vote[0] == commitment:
                self.unsealed_votes[token] = (commitment_key, vote)
                return

        raise Exception('VoteTallier: unsealed commitment not found in sealed votes')

class User:
    def __init__(self, distance):
        self.private_key = PrivateKey.generate()
        self.public_key = self.private_key.public_key
        self.db_key = nacl.utils.random(DB_BITS // 8)
        self.public_key_str = get_key_string(self.public_key)
        self.distance = distance
        self.vote_counter = 0

    def handle_db_challenge(self, challenge):
        # TODO: this is not actually how this works -- should have a keyed random function,
        # 2 registers, use challenge as bit select, etc. buuut....
        return self.db_key

    def set_voting_group(self, group, cachehash=None):
        self.voting_group = group
        if not cachehash:
            cachehash = makehash(voting_group)
        self.voting_group_hash = cachehash

    def do_distance_verification(self):
        esdp = distance_verifier.request_distance_verification(self, epoch)

        sdp = SealedBox(self.private_key).decrypt(esdp)
        sdp = to_signed_message(sdp)
        key_authority.verify_key.verify(sdp)

        _, pdp = bytes2obj(sdp.message)
        self.user_token = validate_pdp(pdp, self.voting_group_hash)

        self.pdp = pdp
        self.sdp = sdp

    def do_sealed_vote(self, vote):
        self.vote = vote
        self.commitment_key = nacl.utils.random(64)
        self.vote_counter += 1

        commitment = blake2b(obj2bytes(self.vote), key=self.commitment_key)
        self.sealed_vote = (commitment, self.vote_counter, self.pdp)
        self.receipt = vote_tallier.do_sealed_vote(self.sealed_vote)

    def do_validate_ledger(self):
        assert vote_tallier.sealed_votes[self.user_token] == self.sealed_vote

        for token, sealed_vote in vote_tallier.sealed_votes.items():
            pdp = sealed_vote[2]
            computed_token = validate_pdp(pdp, self.voting_group_hash)
            assert token == computed_token

    def do_unseal_vote(self):
        vote_tallier.do_unseal_vote(self.commitment_key, self.vote)


#####################

key_authority = KeyAuthority()
distance_verifier = DistanceVerifier()
vote_tallier = VoteTallier()

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

with Timer() as t:
    distance_verifier.set_voting_group(voting_group)
    vote_tallier.set_voting_group(voting_group)
    cachehash = makehash(voting_group)
    for user in users:
        user.set_voting_group(voting_group, cachehash)
print("set voting group in {}".format(t.elapsed))

# phase: distance verification
with Timer() as t:
    for user in users:
        user.do_distance_verification()
print("did {} distance verification in {}".format(len(users), t.elapsed))

# phase: sealed_vote
with Timer() as t:
    for user in users:
        user.do_sealed_vote('eli')
print("did {} sealed votes in {}".format(len(users), t.elapsed))

# phase: validate ledger === "done in parallel"
with Timer() as t:
    user.do_validate_ledger()
print("validated ledgers (PARALLEL) in  {}".format(t.elapsed))

# phase: unseal vote
with Timer() as t:
    for user in users:
        user.do_unseal_vote()
print("unsealed {} votes in  {}".format(len(users), t.elapsed))

# phase: tally!
with Timer() as t:
    tally = tally_votes()
    print(tally)
print("tallied in {}".format(t.elapsed))
