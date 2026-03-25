---
title: "Crackmes : Hekliet's keygenme"
description: "Reverse engineering a custom easy keygen to find a valid licence key using static and script"
pubDatetime: 2026-03-19T00:00:00Z
tags: ["reverse-engineering", "crackmes", "keygen", "ctf"]
draft: false
---


# Crackmes : Hekliet's keygenme (Medium)
* Author : hekliet
* Difficulty: 3.0 Rate!
* Quality: 4.0 Rate!
* Download : https://crackmes.one/crackme/69723bb7d735cd51e7a1aa78
## Key takeaways
* **Knowledge :** Key Generator, Cycle
* **Technique :** Static Analysis, Script Python, Encryption
* **Programming language** : C/C++.
## Case Summary

The program requires 2 parameters which are `name` and `Key`, then will get `name` to create `a` and `b` while `key` will supply radius `r1`,`r2`, then if the function `is_key_valid()` return true, this problem is finished.

## Analyst

![1.png](https://raw.githubusercontent.com/KajriVN/Blog/main/src/assets/images/HeklietKeyGen/1.png)
Firstly, I will check in the main() function and try to execute it. There are 2 requirements that I have to type in. 

Following the code, I paid attention that the binary will read 2 global variables which are `name` and 32 bytes `key` in hexdecimal format, then call `KeyGen()` function with `name` variable.

![2.png](https://raw.githubusercontent.com/KajriVN/Blog/main/src/assets/images/HeklietKeyGen/2.png)
In `KeyGen()` function, it will return to 2 global variables `a` and `b`, they are both center in circle.

![3.png](https://raw.githubusercontent.com/KajriVN/Blog/main/src/assets/images/HeklietKeyGen/3.png)

Finally, we must address this fomular: $$F = H(r_1^2 + a \cdot r_1 + b) + V(r_2^2 + a \cdot r_2 + b)$$

While : 
* `r1` is 16 bytes first in `key` input and last is `r2`
* `a` and `b` are both global variables.

Finally, we just simply find 2 two `a` and `b` variables through `KeyGen()`. 

This is script python IDA to get these variables 

```python
import idc

import struct

import math

  

def get_double(addr):

return struct.unpack('d', struct.pack('Q', idc.get_qword(addr)))[0]

  

def double_to_hex(f):

return hex(struct.unpack('<Q', struct.pack('<d', f))[0]).replace('L', '')

  

# 1. Chạy qua KeyGen trước (đặt breakpoint ở call is_key_valid)

# 2. Lấy giá trị a và b sau khi KeyGen đã tính xong

addr_a = idc.get_name_ea_simple("a")

addr_b = idc.get_name_ea_simple("b")

  

if addr_a != idc.BADADDR and addr_b != idc.BADADDR:

A = get_double(addr_a)

B = get_double(addr_b)

print(f"[+] Da lay duoc: A = {A}, B = {B}")

# Giai phuong trinh: R^2 + AR + B = 0

delta = A*A - 4*B

if delta < 0:

print("[-] Delta am, phương trình phức tạp hơn rồi...")

else:

r_sol = (-A + math.sqrt(delta)) / 2.0

print("-" * 30)

print("KẾT QUẢ KEY CẦN NHẬP (DẠNG HEX):")

print(f"v5 (Key 1): {double_to_hex(r_sol)[2:]}")

print(f"v4 (Key 2): {double_to_hex(r_sol)[2:]}")

print("-" * 30)

print("Lưu ý: Nhập 2 chuỗi hex trên cách nhau bởi dấu cách.")

else:

print("[-] Khong tim thay bien a hoac b.")
```

<<<<<<< HEAD
> P/s : we just figure out only 16 bytes-first and repeat it in 16 bytes-last, thus leading to solve this issue :)))
=======
> P/s : we just figure out only one 16 bytes-first and repeat it in 16 bytes-last, thus leading to solve this issue :)))
>>>>>>> 3d49b81124495c370618d1638842fcc164ef1599
