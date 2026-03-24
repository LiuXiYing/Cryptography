def caesar_encrypt(plaintext, shift):
    """凯撒密码加密函数"""
    result = ""
    for char in plaintext:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            result += encrypted_char
        else:
            result += char
    return result