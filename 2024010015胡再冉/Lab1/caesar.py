def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

if __name__ == "__main__":
    plaintext = "Hello, Yuxi Normal University!"
    shift = 3
    encrypted = caesar_encrypt(plaintext, shift)
    decrypted = caesar_decrypt(encrypted, shift)
    print(f"原文: {plaintext}")
    print(f"加密后: {encrypted}")
    print(f"解密后: {decrypted}")