import json
from base64 import b64encode, b64decode
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def encrypt(data, key, algorithm):
    if algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_CBC)
    elif algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC)
    else:
        raise ValueError("Invalid algorithm. Choose 'DES' or 'AES'.")

    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), cipher.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return json.dumps({'iv': iv, 'ciphertext': ct})


def decrypt(json_input, key, algorithm):
    b64 = json.loads(json_input)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])

    if algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Invalid algorithm. Choose 'DES' or 'AES'.")

    pt = unpad(cipher.decrypt(ct), cipher.block_size)
    return pt.decode('utf-8')


def write_to_file(filename, content):
    with open(filename, 'w') as file:
        file.write(content)


def read_from_file(filename):
    with open(filename, 'r') as file:
        return file.read()


if __name__ == '__main__':

    # Choose the file for encryption
    input_file = input("Введіть шлях до файлу, який ви хочете зашифрувати: ")

    # Choose the encryption algorithm (DES or AES)
    encryption_algorithm = input("Оберіть алгоритм шифрування (DES або AES): ").upper()

    # Read the data from the chosen file
    data_to_encrypt = read_from_file(input_file)

    # Generate a random key based on the chosen algorithm
    if encryption_algorithm == 'DES':
        encryption_key = get_random_bytes(8)
    elif encryption_algorithm == 'AES':
        encryption_key = get_random_bytes(16)
    else:
        raise ValueError("Неправильний алгоритм. Оберіть 'DES' або 'AES'.")

    # Encrypt the data
    encrypted_data = encrypt(data_to_encrypt, encryption_key, encryption_algorithm)

    # Save the encrypted data to a file
    output_file_encrypted = input("Введіть шлях для збереження зашифрованого файлу: ")
    write_to_file(output_file_encrypted, encrypted_data)

    # Choose the file for decryption
    input_file_decrypted = input("Введіть шлях до файлу, який ви хочете розшифрувати: ")

    # Read the encrypted data from the chosen file
    encrypted_data_to_decrypt = read_from_file(input_file_decrypted)

    # Decrypt the data
    decrypted_data = decrypt(encrypted_data_to_decrypt, encryption_key, encryption_algorithm)

    # Choose the file for storing the decrypted data
    output_file_decrypted = input("Введіть шлях для збереження розшифрованого файлу: ")
    write_to_file(output_file_decrypted, decrypted_data)

    # Display the decrypted data
    # print("Розшифроване повідомлення:", decrypted_data)
   