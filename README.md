# Template
```
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

exe = './sign-in'

elf = context.binary = ELF(exe)

sla  = lambda r, s: conn.sendlineafter(r, s)
sl   = lambda    s: conn.sendline(s)
sa   = lambda r, s: conn.sendafter(r, s)
se   = lambda s: conn.send(s)
ru   = lambda r, **kwargs: conn.recvuntil(r, **kwargs)
rl   = lambda : conn.recvline()
uu32 = lambda d: u32(d.ljust(4, b'\x00'))
uu64 = lambda d: u64(d.ljust(8, b'\x00'))

def sign_up(username, password):
    sla(b'> ', b'1')
    sa(b'username: ', username)
    sa(b'password: ', password)

def sign_in(username, password):
    sla(b'> ', b'2')
    sa(b'username: ', username)
    sa(b'password: ', password)

def remove_account():
    sla(b'> ', b'3')

def get_shell():
    sla(b'> ', b'4')

conn = start()

conn.interactive()

```
