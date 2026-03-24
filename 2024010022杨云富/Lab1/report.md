# Lab1 凯撒密码实验报告

## 一、实验目的
- 理解凯撒密码的加密与解密原理
- 掌握 Python 实现凯撒密码的方法
- 学会编写规范的实验报告

## 二、实验原理
凯撒密码是一种替换加密算法，通过将字母表中的每个字母偏移固定位数（密钥）实现加密。
- 加密公式：`c = (p + k) mod 26`
- 解密公式：`p = (c - k) mod 26`
其中 `p` 为明文字母，`c` 为密文字母，`k` 为偏移量（密钥）。

## 三、实验代码
```python
def caesar_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isupper():
            ciphertext += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        elif char.islower():
            ciphertext += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            ciphertext += char
    return ciphertext

def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isupper():
            plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        elif char.islower():
            plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
        else:
            plaintext += char
    return plaintext
## 四、实验结果
- 测试明文：HELLO WORLD
- 密钥：3
- 加密结果：KHOOR ZRUOG
- 解密结果：HELLO WORLD
- 验证：解密结果与原明文一致，算法实现正确。

## 五、实验总结
本次实验成功实现了凯撒密码的加密与解密功能，掌握了替换密码的基本思想，熟悉了 Python 字符串处理和 Markdown 文档编写规范。
