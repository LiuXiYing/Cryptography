# 哈希链文件认证系统 - Lab6 完整实现
from Crypto.Hash import SHA256

def compute_hash_chain(filename):
    """
    计算文件的哈希链根哈希 h0
    :param filename: 视频文件路径 (test.mp4 / intro.mp4)
    :return: 根哈希的十六进制字符串
    """
    # 1. 以二进制模式读取文件
    with open(filename, "rb") as f:
        file_data = f.read()

    # 2. 按 1KB（1024字节）分块
    block_size = 1024
    blocks = [file_data[i:i+block_size] for i in range(0, len(file_data), block_size)]

    # 3. 反转分块列表，从最后一块开始计算
    blocks.reverse()

    # 4. 迭代计算哈希链
    current_hash = b""  # 初始哈希为空
    for block in blocks:
        # 拼接当前块 + 上一步的哈希值
        data = block + current_hash
        # 计算 SHA256
        hash_obj = SHA256.new(data)
        current_hash = hash_obj.digest()

    # 5. 返回最终根哈希（十六进制格式）
    return current_hash.hex()

if __name__ == "__main__":
    # 验证 test.mp4（正确值：03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8）
    test_result = compute_hash_chain("test.mp4")
    print("test.mp4 根哈希:", test_result)

    # 计算 intro.mp4
    intro_result = compute_hash_chain("intro.mp4")
    print("intro.mp4 根哈希:", intro_result)