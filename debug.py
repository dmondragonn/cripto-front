from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import bytes_to_long, long_to_bytes


def generate_keys(bits=512):

    key = ElGamal.generate(bits, get_random_bytes)
    return key, key.publickey()


def elgamal_encrypt(public_key, message):

    m = bytes_to_long(message.encode())
    k = randint(1, int(public_key.p - 2))

    p, g, y = int(public_key.p), int(public_key.g), int(public_key.y)

    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)


def elgamal_decrypt(private_key, ciphertext):

    c1, c2 = ciphertext

    p, x = int(private_key.p), int(private_key.x)

    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p
    return long_to_bytes(m).decode()


private_key, public_key = generate_keys()

message = "DeiverOdiaatania"
print("Mensaje original:", message)

ciphertext = elgamal_encrypt(public_key, message)
print("Mensaje cifrado:", ciphertext)

decrypted_message = elgamal_decrypt(private_key, ciphertext)
print("Mensaje descifrado:", decrypted_message)
