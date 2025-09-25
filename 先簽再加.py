from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
# 簽名
def sign_message(private_key, message):
    h = SHA256.new(message)
    signature = pss.new(private_key).sign(h)
    return signature

# 驗證簽名
def verify_signature(public_key, message, signature):
    h = SHA256.new(message)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
# 生成 RSA 密鑰對
key = RSA.generate(2048)
# 待加密/簽名的訊息
message0="HElLOO00OooOOOO WWWWWWWWoRLd"
message= message0.encode()
# 創建 RSA-OAEP 密碼器
cipher_rsa = PKCS1_OAEP.new(key)
# 先簽名再加密

signature = sign_message(key, message)
print("簽名後的 message:",signature)
print("\n")
# OAEP加密的最大明文長度计算
max_data_length =key.size_in_bytes() - 2*32-2
 #分塊加密(因明文長度太長)
final_sign=message+signature
encrypted_message = b''
for i in range(0, len(final_sign), max_data_length): 
    block = final_sign[i:i + max_data_length]
    encrypted_block = cipher_rsa.encrypt(block)
    encrypted_message += encrypted_block
print("加密後的 signature:", encrypted_message)
print("\n")
# 分塊解密訊息
decrypted_message=b''
for i in range(0, len(encrypted_message), 256): 
    block = encrypted_message[i:i + 256]
    decrypted_block = cipher_rsa.decrypt(block)
    decrypted_message += decrypted_block
#印出明文(全部的decrypted_message=明文部分+簽名部分) 所以只取前面
print("解密後的 message:",decrypted_message[0:len(decrypted_message)-key.size_in_bytes()].decode())
print("\n")
# 驗證簽名(要分離decrypted_message 分離成明文部分+簽名部分 再丟入驗證簽名的Function)
verification = verify_signature(key.publickey(), decrypted_message[0:len(decrypted_message)-key.size_in_bytes()], decrypted_message[len(decrypted_message)-key.size_in_bytes():len(decrypted_message)])
print("簽名是否吻合:", verification)
