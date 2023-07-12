import hashlib
import base64
from RSA.RSA_OAEP import encrypt_oaep

def hash_message(message):
    sha3 = hashlib.sha3_256()
    sha3.update(message.encode())
    return sha3.digest()

def sign_message(message, private_key):
    message_hash = hash_message(message)
    signature = encrypt_oaep(message_hash, private_key)  # Presume-se que você tenha a função rsa_encrypt
    return signature

def format_signature(signature):
    return base64.b64encode(signature)

def format_message(message, signature):
    return message + '\n' + format_signature(signature).decode()


if __name__ == "__main__":
    d = "-0xb13847742e53dfd13e8079e3b62c441a149451037d82ae3de1d601d7939fbbbb40731e5ba4790bf481873f59282170f626a46112af5e4f74d492785b209f59d8b85629a8e7f4be13cdb0670120ed8d399ab2152a5ba9f41f280a9b4224078d3afe08e7c1a70f6be04ce97dd16842bdb306b8ba05e5473ed2d32eb20f79d2cdc62ba7cb6ef9d662c84b8825dc81d34e827d7b2d78f9939803b8762d17ed13e908b14658d16741b9ff480162255d356d782ff0131d987f8f90c84c961a05060de1aeb70b95e03c9949a18cc56709fc0830c049923f048bdc3166780f25d1382c350eb98cb830c1262ad0f8a0e1a8a52c39cdfe3d25ac48023b2157f8892b069c7"
    d = int(d, 16)
    n = "0x8bf25b0c28b152e1a45ac9c5cfc7ea804c588f00c8fd391ac00c8c1be6e6ba8b1177624f45814f28115c0c56fc2edd79bb15b0b5ac8b91e68bb1dce6db695aa39da23bb73525ad033e8b70a182e215ef7101f946e008248cd84cce246bd1c250adefa1dd662a9a0890bc90e3580f83fda506f613583c85562db4e62ea081b9e6bde8b85f9e4b7757846aba57328db90dc59634a8588a0bf1045dd9bd82d95442b7159eb232dc39521c33791689ed84fd7b3d0e5385ed726c2965250f3f122dbae00df21c48caa4ef0c1c35c65ee813e7e98ba276d9c42c912de6bb07f4a5d96c32739c017f4b4ab5dca521a18e34f123c2ca93b931e6be804db20377e6d599f3"
    n = int(n, 16)
    private_key = (d, n)

    message = "Esta é a mensagem que quero assinar"
    signature = sign_message(message, private_key)
    formatted_message = format_message(message, signature)

    print(formatted_message)