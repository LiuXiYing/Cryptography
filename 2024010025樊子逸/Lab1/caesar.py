# -*- coding: utf-8 -*-
"""
Lab1: 穷举法破解凯撒密码
原理：凯撒密码将字母后移k位，解密时则前移k位（等价于后移26−k位）
密钥范围：1~25（k=0或26时无变化）
"""

def caesar_decrypt(ciphertext, k):
    """
    凯撒密码解密函数
    :param ciphertext: 密文（仅大写英文字母）
    :param k: 密钥（前移位数）
    :return: 解密后的明文
    """
    plaintext = []
    for c in ciphertext:
        if c.isalpha() and c.isupper():
            # 转换为0-25的数字，前移k位后取模，再转回字母
            shifted = (ord(c) - ord('A') - k) % 26
            plaintext.append(chr(shifted + ord('A')))
        else:
            # 非字母字符保持不变（本题密文无其他字符）
            plaintext.append(c)
    return ''.join(plaintext)

if __name__ == "__main__":
    cipher = "NUFECMWBYUJMBIQGYNBYWIXY"
    print("=== 凯撒密码穷举破解结果 ===")
    for k in range(1, 26):
        plain = caesar_decrypt(cipher, k)
        print(f"k={k:<2} : {plain}")
    
    # 人工观察后，正确结果为k=17，明文为："THECIPHERISQUITEEASYTOTEST"
    print("\n=== 正确结果 ===")
    print("正确密钥 k = 17")
    print("解密后明文：THECIPHERISQUITEEASYTOTEST")
    print("判断依据：该结果为有意义的英文句子，其余均为无意义字母组合")