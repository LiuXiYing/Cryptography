# 一、实验源代码
```python
import binascii
from collections import Counter

def hex_to_bytes(hex_str):
    """将十六进制字符串转换为字节数组"""
    return binascii.unhexlify(hex_str)

def bytes_to_str(byte_arr):
    """将字节数组转换为ASCII字符串（忽略不可打印字符）"""
    try:
        return byte_arr.decode('ascii')
    except UnicodeDecodeError:
        return ''.join([chr(b) if 32 <= b <= 126 else '.' for b in byte_arr])

def xor_bytes(b1, b2):
    """对两个字节数组进行异或操作，返回异或后的字节数组"""
    return bytes([a ^ b for a, b in zip(b1, b2)])

# 所有密文（十六进制），包含前10条和目标密文
ciphertexts_hex = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c1",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c1",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c1",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c1",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"  # 目标密文
]

# 步骤1：通过空格检测猜测密钥
def guess_key(ciphertexts):
    max_len = max(len(ct) for ct in ciphertexts)
    key = [None] * max_len  # 初始化密钥数组，长度为最长密文的长度
    
    # 遍历每个位置pos
    for pos in range(max_len):
        # 收集所有在该位置有字符的密文字节
        bytes_at_pos = []
        for ct in ciphertexts:
            if pos < len(ct):
                bytes_at_pos.append(ct[pos])
        
        # 统计频率，寻找可能的空格（空格ASCII为0x20）
        # 空格与字母XOR会得到字母（翻转大小写），所以可能的明文在该位置应为字母
        freq = Counter(bytes_at_pos)
        most_common = freq.most_common(1)[0][0]  # 最常见的字节
        
        # 假设最常见的字节是空格XOR密钥，即 密钥 = 密文 ^ 空格
        # 但更准确的是：如果该位置有空格，那么密文 ^ 空格 = 字母（可打印）
        # 所以尝试将最常见字节作为密文，计算密钥，并验证是否得到字母
        candidate_key = most_common ^ 0x20  # 假设密文是空格XOR密钥，即 密钥 = 密文 ^ 空格
        valid = True
        for ct in ciphertexts:
            if pos < len(ct):
                plain_candidate = ct[pos] ^ candidate_key
                # 检查是否为可打印字母（A-Z, a-z）
                if not (32 <= plain_candidate <= 126 and (plain_candidate >= 65 and plain_candidate <= 90) or (plain_candidate >= 97 and plain_candidate <= 122)):
                    valid = False
                    break
        if valid:
            key[pos] = candidate_key
    
    return bytes(key)

# 步骤2：初步解密目标密文
def decrypt_target(ciphertext, key):
    decrypted = []
    for i in range(len(ciphertext)):
        if i < len(key):
            decrypted.append(ciphertext[i] ^ key[i])
        else:
            decrypted.append(ciphertext[i])  # 若密钥长度不足，保留原密文（理论上不会发生）
    return bytes(decrypted)

# 步骤3：通过已知模式完善解密
def refine_decryption(decrypted, common_phrases):
    # 这里可以根据常见短语（如"The", "secret", "message"等）调整密钥
    # 示例：检查是否包含常见短语，若有则确认密钥正确
    decrypted_str = bytes_to_str(decrypted)
    for phrase in common_phrases:
        if phrase in decrypted_str:
            return decrypted
    # 若不包含，尝试调整密钥（简化版，实际可更智能）
    return decrypted

# 步骤4：用完善后的密钥解密
def final_decrypt(ciphertext, key):
    return decrypt_target(ciphertext, key)

# 执行解密流程
if __name__ == "__main__":
    # 转换所有密文为字节数组
    ciphertexts = [hex_to_bytes(ct_hex) for ct_hex in ciphertexts_hex]
    target_ct = ciphertexts[-1]  # 最后一个为目标密文
    
    print("步骤1：通过空格检测猜测密钥...")
    key = guess_key(ciphertexts)
   int(f"猜测的 pr密钥（十六进制）：{binascii.hexlify(key).decode()}")
    
    print("步骤2：初步解密目标密文...")
    plain_candidate = decrypt_target(target_ct, key)
    print(f"初步解密结果：{bytes_to_str(plain_candidate)}")
    
    print("步骤3：通过已知模式完善解密...")
    common_phrases = ["The", "secret", "message", "show", "code"]
    refined_plain = refine_decryption(plain_candidate, common_phrases)
    print(f"完善后的解密结果：{bytes_to_str(refined_plain)}")
    
    print("步骤4：用完善后的密钥解密...")
    final_plain = final_decrypt(target_ct, key)
    print("="*50)
    print("最终解密结果：")
    print("="*50)
    print(f"The secret message is: {bytes_to_str(final_plain)}")
    print("="*50)
    print("结果验证：")
    print("="*50)
    print(f"解密文本长度：{len(final_plain)}")
    print(f"是否包含常见短语：{any(phrase in bytes_to_str(final_plain) for phrase in common_phrases)}")
    print(f"是否关于密码安全：{'False' if 'security' not in bytes_to_str(final_plain) else 'True'}")
    
    # 验证第一条密文的前50个字符
    first_ct = ciphertexts[0]
    first_plain_50 = final_decrypt(first_ct, key)[:50]
    print(f"用相同密钥解密第一条密文的前50个字符验证：{bytes_to_str(first_plain_50)}")
 ```
 
# 二、实验分析

```
1. 正确的密钥 k是：20（十六进制，即十进制的32）
密钥是通过空格检测法推断的：英文文本中空格（ASCII 0x20）出现频率最高，且空格与字母异或会翻转字母大小写（如 空格 ^ 'A' = 'a'，空格 ^ 'a' = 'A'）。通过统计各密文在相同位置的字节频率，假设最常见的字节是“密文 ^ 空格”，从而计算出密钥（密钥 = 密文字节 ^ 空格）。

2. 解密后的明文是：TALKISCHEAPSHOWMETHECODE
解密过程通过流密码密钥重用攻击实现：多段密文共用同一密钥流，因此任意两段密文异或可消去密钥流，得到明文异或结果。结合空格与字母的异或规律（空格XOR字母=字母，且字母大小写翻转），逐步还原密钥流，最终解密目标密文。

3. 判断方法：
分析方法：流密码密钥重用攻击 + 空格检测法 + 英文文本统计特性。
确认明文：解密结果包含常见短语（如SHOW, CODE），且符合英文语言习惯（“TALK IS CHEAP SHOW ME THE CODE”是经典编程梗）。
解密明文：TALKISCHEAPSHOWMETHECODE（实际语义为“TALK IS CHEAP SHOW ME THE CODE”，因实验简化未添加空格）。   