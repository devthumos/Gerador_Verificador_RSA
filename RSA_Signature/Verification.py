import base64
from RSA.RSA_OAEP import decrypt_oaep
from RSA_Signature.Signature import hash_message

def decrypt_signature(signature, public_key):
    hash_from_signature = decrypt_oaep(signature, public_key)  # Presume-se que você tenha a função rsa_decrypt
    return hash_from_signature

def parse_signed_message(signed_message):
    parts = signed_message.split('\n')
    message = parts[0]
    signature = base64.b64decode(parts[1])
    return message, signature

def verify_message(signed_message, public_key):
    message, signature = parse_signed_message(signed_message)
    try:
        hash_from_signature = decrypt_signature(signature, public_key)
    except AssertionError:
        return False
    message_hash = hash_message(message)
    return message_hash == hash_from_signature