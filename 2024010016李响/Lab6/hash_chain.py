# -*- coding: utf-8 -*-
"""
Lab6 基于哈希链的文件认证系统
功能：计算文件的哈希链根哈希值 h0
"""
from Crypto.Hash import SHA256

def compute_hash_chain(file_path):
    """
    计算文件哈希链根哈希 h0
    :param file_path: 视频文件路径
    :return: 根哈希 h0（十六进制字符串）
    """
    # 1. 以二进制模式读取文件
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    # 2. 转换为十六进制字符串
    hex_str = file_bytes.hex()

    # 3. 按照 1KB（2048 个十六进制字符）分块
    block_size = 2048
    blocks = [hex_str[i:i + block_size] for i in range(0, len(hex_str), block_size)]

    # 4. 反转块列表，从最后一个块开始计算
    blocks.reverse()

    # 5. 迭代计算哈希链
    current_hash = ""
    for block in blocks:
        # 拼接当前块 + 上一步的哈希值
        combine_data = block + current_hash
        # 转换为字节类型
        combine_bytes = bytes.fromhex(combine_data)
        # 计算 SHA256
        hash_obj = SHA256.new(combine_bytes)
        # 更新为下一轮使用的哈希
        current_hash = hash_obj.hexdigest()

    # 最终结果就是根哈希 h0
    return current_hash

if __name__ == '__main__':
    # 验证 test.mp4（老师提供正确结果）
    test_result = compute_hash_chain("test.mp4")
    print("test.mp4 哈希链根哈希 h0：", test_result)

    # 计算 intro.mp4 结果
    intro_result = compute_hash_chain("intro.mp4")
    print("intro.mp4 哈希链根哈希 h0：", intro_result)