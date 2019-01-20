#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py

###########################
# Group Members: Noah Vesely, Weiqiu Liu
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can
#           be imported.

import petlib

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher

def encrypt_message(K, message):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")

    ## YOUR CODE HERE
    aes = Cipher.aes_128_gcm()
    iv = urandom(16)
    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)

    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K 

        In case the decryption fails, throw an exception.
    """
    ## YOUR CODE HERE
    aes = Cipher.aes_128_gcm()
    plain = aes.quick_gcm_dec(K, iv, ciphertext, tag)

    return plain.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
           or (x == None and y == None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x*x*x + a*x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    # ADD YOUR CODE BELOW
    xr, yr = None, None

    # Addition with the neutral element returns the element
    if (x0 is None and y0 is None):
        return (x1, y1)
    elif (x1 is None and y1 is None):
        return (x0, y0)
    elif (x0 == x1 and y0 == y1):
        raise Exception('EC Points must not be equal')

    num = y1.int_sub(y0)
    try:
        denom = x1.int_sub(x0).mod_inverse(p)
    except: # No inverse found; the identity element is its own inverse
        return (None, None)
    lam = num.int_mul(denom).mod(p)
    xr = lam.pow(2).int_sub(x0).int_sub(x1).mod(p)
    yr = lam.int_mul(x0.int_sub(xr)).int_sub(y0).mod(p)

    return (xr, yr)

def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """

    # ADD YOUR CODE BELOW
    xr, yr = None, None

    if (x is None and y is None):
        return (None, None)

    num = x.pow(2).int_mul(3).int_add(a)
    try:
        denom = y.int_mul(2).mod_inverse(p)
    except: # No inverse
        return (xr, yr)
    lam = num.int_mul(denom).mod(p)
    xr = lam.pow(2).int_sub(x.int_mul(2)).mod(p)
    yr = lam.int_mul(x.int_sub(xr)).int_sub(y).mod(p)

    return xr, yr

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    Q = (None, None)
    P = (x, y)

    for i in range(scalar.num_bits()):
        if scalar.is_bit_set(i):
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
        else: # Note this constant-time hack only works because the compiler
              # has not optimized away this branch
            R = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
        P = point_double(a, b, p, P[0], P[1])

    return Q

def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    R0 = (None, None)
    R1 = (x, y)

    for i in reversed(range(0,scalar.num_bits())):
        if not scalar.is_bit_set(i):
            R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R0 = point_double(a, b, p, R0[0], R0[1])
        else:
            R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R1 = point_double(a, b, p, R1[0], R1[1])

    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification
#            using petlib.ecdsa

from hashlib import sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing 
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message, encode=True):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext = message
    if encode:
        plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()
    sig = do_ecdsa_sign(G, priv_sign, digest)

    return sig

def ecdsa_verify(G, pub_verify, message, sig, encode=True):
    """ Verify the ECDSA signature on the message """
    plaintext = message
    if encode:
        plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()
    res = do_ecdsa_verify(G, pub_verify, sig, digest)

    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE:
from math import ceil

from petlib.ec import EcPt
from petlib.hmac import Hmac

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(pub, message, aliceSig = None):
    """ Assume you know the public key of someone else (Bob), 
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """

    ## YOUR CODE HERE
    G, priv_dec, pub_enc = dh_get_key()
    ss = priv_dec * pub
    sk = hkdf(ss.export())
    iv, ciphertext, tag = encrypt_message(sk, message)

    sig = None
    if aliceSig:
        sig = ecdsa_sign(G, aliceSig, iv + ciphertext + str(tag), encode=False)

    return (pub_enc, iv, ciphertext, tag, sig)

def hkdf(ikm, l=16, salt=b"0"*32, info=b""):
    """ HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    https://tools.ietf.org/html/rfc5869

    ARGS:
        ikm  : input keying material
        l    : length of output keying material in octets
        salt : (optional) salt value (defaults to 32 0s)
        info : (optional) context and application specific information
               (defaults to null string)
    
    Returns:
        okm  : output key material
    """
    hash_len = 32
    extractor = Hmac(b"sha256", salt)
    extractor.update(ikm)
    prk = extractor.digest()

    t = b""
    okm = b""
    for i in range(int(ceil(float(l) / hash_len))):
        expander = Hmac(b"sha256", prk)
        expander.update(t + info + bytes([1+i]))
        t = expander.digest()
        okm += t

    return okm[:l]

def dh_decrypt(priv, ciphertext, aliceVer = None):
    """ Decrypt a received message encrypted using your public key, 
    of which the private key is provided. Optionally verify 
    the message came from Alice using her verification key."""

    ## YOUR CODE HERE
    G, _, _ = dh_get_key()
    pub, iv, ciphertext, tag, sig = ciphertext
    if sig:
        if not aliceVer:
            raise Exception('Signature present, but not verification key!')
        elif not ecdsa_verify(G, aliceVer, iv + ciphertext + str(tag), sig, encode=False):
            raise Exception('Signature invalid!')

    if aliceVer and not sig:
        raise Exception('Verification key present, but not signature!')

    ss = priv * pub
    sk = hkdf(ss.export())
    plaintext= decrypt_message(sk, iv, ciphertext, tag)

    return plaintext



## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py

def test_encrypt():
    _, _, pub = dh_get_key()
    G, aliceSig, aliceVer = ecdsa_key_gen()
    message = u'"Education is the passport to the future, for tomorrow '
    'belongs to those who prepare for it today." -- Malcom X'
    pub, iv, ciphertext, tag, sig = dh_encrypt(pub, message, aliceSig)

    assert(type(pub) == EcPt)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16
    assert ecdsa_verify(G, aliceVer, iv + ciphertext + str(tag), sig, encode=False)

def test_decrypt():
    G, priv_bob, pub_bob = dh_get_key()
    G, aliceSig, aliceVer = ecdsa_key_gen()
    message = u"Hello World!"
    pub_alice, iv, ciphertext, tag, sig = dh_encrypt(pub_bob, message, aliceSig)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16
    assert ecdsa_verify(G, aliceVer, iv + ciphertext + str(tag), sig, encode=False)

    m = dh_decrypt(priv_bob, (pub_alice, iv, ciphertext, tag, sig), aliceVer)

    assert m == message

def test_fails():
    from pytest import raises

    G, priv_bob, pub_bob = dh_get_key()
    G, aliceSig, aliceVer = ecdsa_key_gen()
    message = u"Hello World!"

    pub_alice, iv, ciphertext, tag, sig = dh_encrypt(pub_bob, message, aliceSig)

    assert len(iv) == 16
    assert len(ciphertext) == len(message)
    assert len(tag) == 16
    assert ecdsa_verify(G, aliceVer, iv + ciphertext + str(tag), sig, encode=False)

    m = dh_decrypt(priv_bob, (pub_alice, iv, ciphertext, tag, sig), aliceVer)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_bob, (pub_alice, iv, urandom(len(ciphertext)), tag, sig), aliceVer)
    assert 'Signature invalid!' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_bob, (pub_alice, iv, ciphertext, urandom(len(tag)), sig), aliceVer)
    assert 'Signature invalid!' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_bob, (pub_alice, urandom(len(iv)), ciphertext, tag, sig), aliceVer)
    assert 'Signature invalid!' in str(excinfo.value)

    G, priv_test, pub_test = dh_get_key()

    with raises(Exception) as excinfo:
        dh_decrypt(priv_bob, (pub_test, iv, ciphertext, tag, sig), aliceVer)
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_test, (pub_alice, iv, ciphertext, tag, sig), aliceVer)
    assert 'decryption failed' in str(excinfo.value)

    G, aliceSigTest, aliceVerTest = ecdsa_key_gen()
    sigTest = ecdsa_sign(G, aliceSigTest, message, encode=False)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_bob, (pub_alice, iv, ciphertext, tag, sigTest), aliceVer)
    assert 'Signature invalid!' in str(excinfo.value)

    sigTest = ecdsa_sign(G, aliceSig, u"Hello World", encode=False)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_bob, (pub_alice, iv, ciphertext, tag, sigTest), aliceVer)
    assert 'Signature invalid!' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_bob, (pub_alice, iv, ciphertext, tag, sig), aliceVerTest)
    assert 'Signature invalid!' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_bob, (pub_alice, iv, ciphertext, tag, sig))
    assert 'Signature present, but not verification key!' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_bob, (pub_alice, iv, ciphertext, tag, None), aliceVer)
    assert 'Verification key present, but not signature!' in str(excinfo.value)

#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.
from pytest import raises
from time import clock

from petlib.ec import EcGroup, EcPt

R1 = Bn.from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
R2 = Bn.from_hex("100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001")

def time_scalar_mul():
    G = EcGroup(713) # NIST curve
    d = G.parameters()
    a, b, p = d["a"], d["b"], d["p"]
    g = G.generator()
    gx0, gy0 = g.get_affine()

    def average_time(func, scalar_name, samples=20):
        scalar = globals()[scalar_name]
        times = []
        for i in range(samples):
            t1 = clock()
            func(a, b, p, gx0, gy0, scalar)
            t2 = clock()
            times.append(t2-t1)

        mean = reduce((lambda x, y: x + y), times) / samples
        print('{}, {}, mean of {} samples: {}'.format(
            func.__name__, scalar_name, samples, mean))

    average_time(point_scalar_multiplication_double_and_add, 'R1')
    average_time(point_scalar_multiplication_double_and_add, 'R2')
    average_time(point_scalar_multiplication_montgomerry_ladder, 'R1')
    average_time(point_scalar_multiplication_montgomerry_ladder, 'R2')

if __name__ == '__main__':
    time_scalar_mul()