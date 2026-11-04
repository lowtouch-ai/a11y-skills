from Crypto.Cipher import AES
IV = b"0123456789abcdef"
def enc(k, d):
    return AES.new(k, AES.MODE_ECB).encrypt(d)
