# python_sm2_encrypt_decrypt
Python 兼容java的hutool、bouncycastle加解密 sm2算法

Hutool的SM2实现通常默认使用 C1C3C2 模式。
gmssl 库中，CryptSM2 类的 mode 参数控制这个行为：

    mode=0: C1C2C3 (C1 || C2 || C3)
    mode=1: C1C3C2 (C1 || C3 || C2)

同样的，要使用asn1参数 做到和Java版本一致


目标是：Java的加密文本，可以在python中解析，或互相解析

Java版本的样例：
```
package com.zx.web.controller.common;

import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import com.zx.common.utils.sign.Base64;

import static org.checkerframework.checker.units.UnitsTools.s;

public class java {
    public static void main(String[] args) {

        String pri = "";
        String pub = "";
        
        String s = "hello";
        SM2 sm3 = SmUtil.sm2(Base64.decode(pri), Base64.decode(pub));
        System.out.println(sm3.encryptBcd(s, KeyType.PublicKey));

        SM2 sm2 = SmUtil.sm2(Base64.decode(pri), Base64.decode(pub));
        String ss = "04E1744B4220EECB843EC354EDC1ABD3938FC6AF8E234D99A0ED018409871D80D3F41E0AC3F46536A732EC580DE6D1C90132485995C1C226DEC501BA2A0AB018600621ACDE7F27F5A2E821A5D67A24DF53CC88007E63D5F136D93E5D6B26F8CAB1CFA31AD741";
        System.out.println(sm2.decryptStrFromBcd(ss, KeyType.PrivateKey));



    }
}

```


Python版本的样例:
```
import base64
import json

from asn1crypto import keys
from gmssl import sm2


# ========== DER → 裸十六进制 ==========
def der_private_to_hex(pri_b64: str) -> str:
    der = base64.b64decode(pri_b64)
    pk_info = keys.PrivateKeyInfo.load(der)
    d_native = pk_info['private_key'].parsed['private_key'].native
    hex_str = f'{d_native:064x}' if isinstance(d_native, int) else d_native.hex().rjust(64, '0')
    return hex_str


def der_public_to_hex(pub_b64: str) -> str:
    der = base64.b64decode(pub_b64)
    pub_info = keys.PublicKeyInfo.load(der)
    pub_bytes = pub_info['public_key'].native
    if pub_bytes[0] == 4:  # 去掉 0x04 前缀
        pub_bytes = pub_bytes[1:]
    hex_str = pub_bytes.hex().rjust(128, '0')
    return hex_str


# ========== 加 / 解密 ==========
# sm2_encrypt_bcd
def encrypt(pub_hex: str, data) -> str:
    print(f"pub_hex: {pub_hex}")
    print(f"data: {data}")
    if isinstance(data, (dict, list)):
        data = json.dumps(data, ensure_ascii=False)
    crypt = sm2.CryptSM2(public_key=pub_hex, private_key=pri_hex, mode=1, asn1=True)
    cipher = crypt.encrypt(data.encode())  # bytes
    return cipher.hex().upper()  # Hutool 的 BCD 大写格式


# sm2_decrypt_bcd
def decrypt(pri_hex: str, cipher_bcd: str) -> str:
    print(pri_hex)
    # pri_hex = pri_hex.upper()
    crypt = sm2.CryptSM2(public_key=pub_hex, private_key=pri_hex, mode=1, asn1=True)
    plain = crypt.decrypt(bytes.fromhex(cipher_bcd))
    print(plain)
    return plain.decode('utf-8')

# ========== 自测 ==========
if __name__ == '__main__':

    PRI_B64 = ''  # 替换为实际私钥
    PUB_B64 = ''  # 替换为实际公钥

    pri_hex = der_private_to_hex(PRI_B64)
    pub_hex = der_public_to_hex(PUB_B64)

    data = {"method": "test"}
    cipher = encrypt(pub_hex, data)
    print("cipher:", cipher)

    plain = decrypt(pri_hex, cipher)
    print("plain :", plain)

    cipher_from_java = "04E1744B4220EECB843EC354EDC1ABD3938FC6AF8E234D99A0ED018409871D80D3F41E0AC3F46536A732EC580DE6D1C90132485995C1C226DEC501BA2A0AB018600621ACDE7F27F5A2E821A5D67A24DF53CC88007E63D5F136D93E5D6B26F8CAB1CFA31AD741"

    decrypted_response = decrypt(pri_hex, cipher_from_java)
    print("decrypted_response:", decrypted_response)



```
