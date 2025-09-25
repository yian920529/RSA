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
# 先加密再簽名

encrypted_message = cipher_rsa.encrypt(message)
print("加密後的 message:",encrypted_message)
print("\n")
signature = sign_message(key, encrypted_message)
print("簽名後的 ciphertext:", signature)
print("\n")
# 驗證簽名
verification = verify_signature(key.publickey(), encrypted_message, signature)
print("簽名是否吻合:", verification)
print("\n")
# 解密訊息
decrypted_message = cipher_rsa.decrypt(encrypted_message)
print("解密後的 message:",decrypted_message.decode())
