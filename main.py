"""
1) Gere uma chave AES aleatória de 128 bits.
2) Use a chave para cifrar o arquivo com o algoritmo AES.
3) Para o RSA, primeiro gere um par de chaves (públicas e privadas) de 1024 bits ou mais.
4) Cifre a chave AES com a chave pública RSA do destinatário.
5) Concatene a chave AES cifrada e o arquivo cifrado. Você pode adicionar um separador ou armazenar o tamanho da chave para facilitar a divisão mais tarde.
6) Para assinar, primeiro calcule o hash do arquivo cifrado.
7) Cifre o hash com sua chave privada RSA. Isto é considerado a assinatura.
8) Concatene a assinatura com a mensagem. Novamente, adicione um separador ou armazene o tamanho da assinatura para divisão posterior.
9) Codifique tudo em base64 para garantir a compatibilidade com sistemas que só lidam com texto.
"""



import base64
import os

from AES.AES_ECB import pad_pkcs7, unpad_pkcs7, generate_128_bit_key, aes_ecb_encryption, aes_ecb_decryption
from RSA.RSA_OAEP import generate_prime_number, calculate_private_key, encrypt_oaep, decrypt_oaep
from RSA_Signature.Signature import hash_message, sign_message, format_signature, format_message
from RSA_Signature.Verification import decrypt_signature, parse_signed_message, verify_message

from typing import Tuple, Callable

Key = Tuple[int, int]

def decode_from_base64(encoded_text: str) -> str:
    '''Decode a base64-encoded string to UTF-8'''
    decoded_bytes = base64.b64decode(encoded_text.encode('utf-8'))
    decoded_text = decoded_bytes.decode('utf-8')
    return decoded_text

def encode_bytearray_to_base64(data: bytearray) -> str:
    '''Encode a bytearray to base64'''
    encoded_bytes = base64.b64encode(data)
    encoded_text = encoded_bytes.decode('utf-8')
    return encoded_text


def aes_encrypt(hex_key:  str):
    # Implementar a cifração AES aqui
    with open(r"TXT_FILES\original.txt", "r", encoding="utf-8") as file:
        plaintext = file.read()

    padded_plaintext = pad_pkcs7(bytearray(plaintext, "utf-8"))
    padded_ciphertext = aes_ecb_encryption(padded_plaintext, bytearray.fromhex(hex_key))

    print(padded_ciphertext)
    with open(r"TXT_FILES\aes_enc.txt", "wb") as file:
        file.write(padded_ciphertext)
    

def aes_decrypt(hex_key: str):
    # Implementar a decifração AES aqui
    with open(r"TXT_FILES\aes_enc.txt", "rb") as file:
        ciphertext = file.read()

    padded_recovered_plaintext = aes_ecb_decryption(ciphertext, bytearray.fromhex(hex_key))
    recovered_plaintext_without_padding = unpad_pkcs7(padded_recovered_plaintext)

    print(recovered_plaintext_without_padding)
    with open(r"TXT_FILES\aes_dec.txt", "w", encoding="utf-8") as file:
        file.write(decode_from_base64(encode_bytearray_to_base64(recovered_plaintext_without_padding)))


def rsa_encrypt(pub_key: Key):
    with open(r"TXT_FILES\original_rsa.txt", "r", encoding="utf-8") as file:
        plaintext = file.read()

    ciphertext = encrypt_oaep(plaintext.encode("ascii"), pub_key)

    with open(r"TXT_FILES\rsa_enc.txt", "wb") as file:
        file.write(ciphertext)


def rsa_decrypt(private_key):
    with open(r"TXT_FILES\rsa_enc.txt", "rb") as file:
        ciphertext = file.read()

    recovered_plaintext = decrypt_oaep(ciphertext, private_key)

    with open(r"TXT_FILES\rsa_dec.txt", "wb") as file:
        file.write(recovered_plaintext)



def keygen():
    rsa_key_size = 2048
    prime_number_bit_length = rsa_key_size // 2

    # Generate prime numbers p and q
    p = generate_prime_number(prime_number_bit_length)
    q = generate_prime_number(prime_number_bit_length)

    # Calculate public key
    n = p * q
    e = 65537

    # Calculate private key
    d = calculate_private_key(e, p, q)

    pub_key, private_key = ((e, n), (d, n))

    return pub_key, private_key

def rsa_signature(private_key: Key):
    with open(r"TXT_FILES\original_rsa.txt", "r", encoding="utf-8") as file:
        plaintext = file.read()
    print(plaintext)

    signature = sign_message(plaintext, private_key)
    signed_message = format_message(plaintext, signature)

    with open(r"TXT_FILES\rsa_signed.txt", "w", encoding="utf-8") as file:
        file.write(signed_message)

def rsa_verify(public_key: Key):
    with open(r"TXT_FILES\rsa_signed.txt", "r", encoding="utf-8") as file:
        signed_message = file.read()

    is_valid = verify_message(signed_message, public_key)

    if is_valid:
        print("Válido!")
    else:
        print("Inválido!")

if __name__ == "__main__":
    header = "\t\t___Trab 02___\n"
    menu = """
    1) Gerar Chave AES Hexadecimal 128 bit
    2) Cifrar AES
    3) Decifrar AES
    4) Gerar Chave RSA Pública e Privada
    5) Cifrar RSA OAEP
    6) Decifrar RSA OAEP
    7) Assinar RSA
    8) Verificar Assinatura
    9) Sair"""

    while True:
        print(header)
        print(menu)
        op = input("\tSelecione uma Opção: ")

        if op == "1":
            print("Chave gerada:", generate_128_bit_key())
        elif op == "2":
            chave = input("Insira a Chave Hexadecimal: ")
            aes_encrypt(chave)
        elif op == "3":
            chave = input("Insira a Chave Hexadecimal: ")
            aes_decrypt(chave)
        elif op == "4":
            pub_key, private_key = keygen()
            print("Chave Pública:", (hex(pub_key[0]), hex(pub_key[1])))
            print("Chave Privada:", (hex(private_key[0]), hex(private_key[1])))
        elif op == "5":
            e = input("Insira Sua Chave Pública e: ")
            n = input("Insira Sua Chave Pública n: ")
            ## Tive que colocar de forma bruta, pq o Python não estava conseguindo converter
            # e = hex(65537)
            # n = hex(11391414030755469112127862034724578561640516293239400385294413978067777436626851927063621587042403852964475278950926583850956801122691538677886978585248817179463643039795531230121328762974983532283625673127255175003505890881022511804190869506554671291785770379986112822175741363220949878820419180946043135115497824170282504010689979627791302361269405483217579006776348294734502318241997717202900276810603001503679888214853623376844586527573501121712748641276574317173288788760982635870275652967070450465179540869559375395228085822312180723297177808936842388610207755194738320417402402791343176035636801813151748110753)
            #e = 65537
            #n = 0x9bfe71b28a9b334969fcc9723613ca2fe090c8870132db738c77093cc7a254b19179a11f0df5e3cd09d5d47267749e284e171a3245caaf21780fe0cd55c6a2ca56d01562c30c4b0fd1317443b47c0c5a6d87c92a2098e3d86b6f702bdd59083b2095e82f4a12e15e3bb77dae4605d51901580068397bc211e208b705dd1c93e041f087dddb04089315b24ed960019e4cde1cdef05dd728a504be0466b65a20c8412068b9e8d060b3b64a84ec7971252da15e81bec1a6f44d3e7064798f25d8f9f64a4f9d0a06b07564172cd2b7f7bd720ae5ad959b0438e56be3e13497d9dc884e25c88282f4e5a9cce083305a07303308b669e5a05455b355787b98d9ac3829
            #n = 19033092928827108302399082925037868177828371508333681956700242869014617892590628158666512745660617424552776528738649567730624565461703205207398283512076878534428192941789497574612200352307944314304499732330046275650555600688914049934020912825611959947605098324224557915624480887271096441919976343659848668189274574156949177661653256346013337286978977417769979217302877739726327674614124464702178591295057976612823013818806362759598689067843094258286717215042004700009637018339261615593899244559498716580378199654749713767537253249749406402999478592339042014088216140569903172173281572206490106587822985784387473168927
            #rsa_encrypt((int(e), int(n)))
            rsa_encrypt((int(e, 16), int(n, 16)))
            print("escrito")
        elif op == "6":
            d = input("Insira Sua Chave Privada d: ")
            n = input("Insira Sua Chave Privada n: ")
            rsa_decrypt((int(d, 16), int(n, 16)))

        elif op == "7":
            d = input("Insira Sua Chave Privada d: ")
            n = input("Insira Sua Chave Privada n: ")
            rsa_signature((int(d, 16), int(n, 16)))

        elif op == "8":
            e = input("Insira Sua Chave Pública e: ")
            n = input("Insira Sua Chave Pública n: ")
            rsa_verify((int(e, 16), int(n, 16)))
            

        elif op == "9":
            exit(1)


        input("Pressione Enter para Continuar!")



    