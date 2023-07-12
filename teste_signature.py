import hashlib
import base64
from RSA.RSA_OAEP import encrypt_oaep, decrypt_oaep

## ASSINA

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

## VERIFICA ASSINATURA

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



if __name__ == "__main__":
    d = "-0xb13847742e53dfd13e8079e3b62c441a149451037d82ae3de1d601d7939fbbbb40731e5ba4790bf481873f59282170f626a46112af5e4f74d492785b209f59d8b85629a8e7f4be13cdb0670120ed8d399ab2152a5ba9f41f280a9b4224078d3afe08e7c1a70f6be04ce97dd16842bdb306b8ba05e5473ed2d32eb20f79d2cdc62ba7cb6ef9d662c84b8825dc81d34e827d7b2d78f9939803b8762d17ed13e908b14658d16741b9ff480162255d356d782ff0131d987f8f90c84c961a05060de1aeb70b95e03c9949a18cc56709fc0830c049923f048bdc3166780f25d1382c350eb98cb830c1262ad0f8a0e1a8a52c39cdfe3d25ac48023b2157f8892b069c7"
    #d = "0x4b95ad0e62f932902e0e5a3c9d1a3ff6a7c46743900315c751dcefdacb7fa6d524a581a583a60b554e0cf839a6b84fb46d90cdcf90069104360c76cbe01a3d27cf7c169a165a3b589fccb9a0b8ed6e7d14f27bdcdc092fb37d4a10737ea58423194cf7e2dd5853e89b34bd2d771a683229e0ce6e48d5df12a6759b781605d82841b8ee5472476cd6ee6536a5284afd6e115a67239d94ad8c02690e01a1f88b03365f5a7231194e6237b23344a7a2ac80ec2802780653e52784a62da69a09f3912f537c766d5aea4427d174ee0fe5185f27d8396d04c575411528e4ba9b5646fcd22be0c79941532b76a47f75301b20def99324845810c46913fdd6d117b5ef59"
    d = int(d, 16)
    n = "0x8bf25b0c28b152e1a45ac9c5cfc7ea804c588f00c8fd391ac00c8c1be6e6ba8b1177624f45814f28115c0c56fc2edd79bb15b0b5ac8b91e68bb1dce6db695aa39da23bb73525ad033e8b70a182e215ef7101f946e008248cd84cce246bd1c250adefa1dd662a9a0890bc90e3580f83fda506f613583c85562db4e62ea081b9e6bde8b85f9e4b7757846aba57328db90dc59634a8588a0bf1045dd9bd82d95442b7159eb232dc39521c33791689ed84fd7b3d0e5385ed726c2965250f3f122dbae00df21c48caa4ef0c1c35c65ee813e7e98ba276d9c42c912de6bb07f4a5d96c32739c017f4b4ab5dca521a18e34f123c2ca93b931e6be804db20377e6d599f3"
    #n = "0xdc9edab4c2df0e35efc52bcdf6575f05121566b19b1499ace0d7a5838e3d6f81585bbd9600b3ad71edda0f02f6bae657ebb81e035f7d652cdac80fdff8c5cf27f84a97188efac939a015161fcb420af38deef9aa2514191759b0f6106e49a9c9c481dada090b2d2c201f4a544e7cb3e0c884fde15df083fda55c3a07d6a832ca86246f5b8916747e118ed56b46c2de13ba9d81d8db2b103b537b873984c03877ef7506b91fb1897c94c235fe713db6ff87d16076a20af01c600b773fad701a238b6b9355cde97bcf11b91fce4a03455b8874286d86244e831903b85ce25b33d124c4c1e852b82ceabda1b0db165aad42f235a59b14e2b8e74aa3a0cba23ded43"
    n = int(n, 16)

    e = "0x10001"
    e = int(e, 16)

    #n = "0x8bf25b0c28b152e1a45ac9c5cfc7ea804c588f00c8fd391ac00c8c1be6e6ba8b1177624f45814f28115c0c56fc2edd79bb15b0b5ac8b91e68bb1dce6db695aa39da23bb73525ad033e8b70a182e215ef7101f946e008248cd84cce246bd1c250adefa1dd662a9a0890bc90e3580f83fda506f613583c85562db4e62ea081b9e6bde8b85f9e4b7757846aba57328db90dc59634a8588a0bf1045dd9bd82d95442b7159eb232dc39521c33791689ed84fd7b3d0e5385ed726c2965250f3f122dbae00df21c48caa4ef0c1c35c65ee813e7e98ba276d9c42c912de6bb07f4a5d96c32739c017f4b4ab5dca521a18e34f123c2ca93b931e6be804db20377e6d599f3"
    n = "0xd4adfd41ffc46ab801d1b91b3995a586a32d3bf5564ed85f12e864552a4baf9aabc7bca805d2ee96c1260dd9f267c4f6e93f30658973d9799542713b4df03431c149b3bc0b377c8d643d30255dbfc598bb21440f72fe894a0ded157d0045093e15c54195346834cbb9dfa66684976f8bd32a54556003441dddee989996d64e2ef6b314d75667d40846e2fe55a8e7c54ba1f8b1d69a5961387894c798d3fa4c090c6df7ae2691b2d42138189c3e9e49e4a10a568cd414463df12b3151931a23734bcf7483838b834ea3bc10287bd40e77b824b79f0d16affa07add45e28d52a6f90b011a0f0f646717b573fcc9ca799c8b9004bbdfc7724c6c131bb765f39913f"
    n = int(n, 16)


    private_key = (d, n)
    public_key = (e, n)

    message = "Esta é a mensagem que quero assinar"
    signature = sign_message(message, private_key)
    signed_message = format_message(message, signature)
    print("Deu certo")
    # Verificando a assinatura
    is_valid = verify_message(signed_message, public_key)

    print("A assinatura é válida?", is_valid)
    print(signed_message)

    with open(r"TXT_FILES\rsa_signed.txt", "w", encoding="utf-8") as file:
        file.write(signed_message)