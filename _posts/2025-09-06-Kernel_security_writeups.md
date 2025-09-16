---
title: 'Kernel security module on pwn college'
date: 2025-09-06
permalink: /posts/2025/09/kernel-security/
tags:
  - Linux Kernel
  - CTF
  - pwn college
---

This is a series of writeups to introductory Linux Kernel security challenges on [kernel-security](https://pwn.college/system-security/kernel-security/). Since platform policy does not want full solutions get leaked so just core ideas and a few snippets(not full exploits) are provided.

## Level 1-4

Straightforward crackmes and just open kernel module files(.ko) in decompliers to check for password, to interact with the module using following snippet:

```
void level1_4() {
    char* passwd = "password";
    int fd = open(DEVICE_PATH, O_WRONLY);
    // If the module implements device_write use this
    write(fd, passwd, strlen(passwd));
    // If the module implements device_ioctl, use this instead
    written = ioctl(fd, IOCTL_CMD, passwd);
    printf("Password written to the device successfully.\n");
    // Get flag according to kernel module functions
    // 1. If written to device
    system("cat /proc/pwncollege");
    // 2. If written by printk
    system("dmesg")
    // 3. If escalate privileges to root
    system("cat /flag");
    close(fd);
}
```
## Level 5

Again open kernel module in decompilers and it can be seen that still cmd code 1337 is neede, and the device_ioctl is executing arg a3 as a function. On the other hand there is a win() function that escalates privilege, so the solution is to find out the addr of win() by checking symbols in /proc/kallsyms under practice mode and input it the way similar to above levels.

(To be honest I think this a bit counter-intuitive as you need to get in root mode first, get information and back to user mode and get root again...)

## Level 6

Open kernel module in decompilers, it is taking an address(arg a2) and copying 4096 bytes data into kernel, then executes it, so it is clear that a piece of shellcode is needed. Notice that under kernel mode those syscalls are not useful anymore, instead execute commit_creds(prepare_kernel_cred(0)), also to find address of the two functions here, check /proc/kallsyms as level 5. Use asm() function in pwntools to assemble and get machine code and write to the device, remember to set context.arch='amd64' (or 'i386' if on 32-bit machines)

## Level 7

Follows the device_ioctl of kernel module:


<img width="543" height="514" alt="image" src="https://github.com/user-attachments/assets/e8fa988a-5cdb-42c0-8007-367daac4a72a" />

It can be noticed that for the input buffer a3, it is parsed in following format:

| Content Length | Content | Address |
|---|---|---|
| 8 bytes | variable, 4096 at most | 8 bytes |

Therefore the solution is still use kernel shellcode in level 6, but prepare its length and the address it will be placed. For the address, use command ```vm debug``` provided, set breakpoint at "call rax" in the function, then trigger the device_ioctl function by randomly sending something to the device. After finding out the address, input length(8 bytes)+content with empty spaces(4096 bytes)+address(8 bytes)=4112 bytes to the device and cat flag.

## Level 8

The difference for this level is that the module is loaded by the userspace binary and it is expected to communicate to kernel through the userspace binary. Follows show the user binary which takes in some shellcode that does not allow syscalls other than sys_write:

<img width="806" height="561" alt="image" src="https://github.com/user-attachments/assets/d1329e72-e159-4462-9228-06e112750e20" />

The kernel module is still rather straightforward that takes in a piece of shellcode and executes:

<img width="790" height="256" alt="image" src="https://github.com/user-attachments/assets/2c7d14c1-2be8-4394-9a29-fe8cc714d4b2" />

Essentially there are two key points in solving this: 1) getting root privileges which is similar as before; 2) remove the seccomp constraint, so that when returning from kernel shellcode, flag can be opened and read to write out. 

To do this, dive into the creds struct which is used for privileges before and checking its "parent", the task struct includes a field called flag, will lead to a flag called TIF_SECCOMP which is in charge of enabling seccomp:

<img width="447" height="172" alt="image" src="https://github.com/user-attachments/assets/c251df85-11be-4a39-bc13-1691abef2db2" />

<img width="375" height="90" alt="image" src="https://github.com/user-attachments/assets/b8a43785-a0ba-4b79-8b79-45035c6c2e2c" />

In short, to disable the seccomp, try do this in kernel space:

```current->thread_info.flags &= ~(1 << TIF_SECCOMP)```

where current is a macro to get the current task struct, but this involves another question: how to get that current in assembly?(Since the input is shellcode through the userland binary)

The answer is that this could be obtained by searching Linux source tree for places that references macro current and check corresponding assembly, for example one such place is commit_creds:

<img width="652" height="94" alt="image" src="https://github.com/user-attachments/assets/f8e04cb0-d75c-4c9f-aeec-dbbbdd4d85af" />
<img width="740" height="124" alt="image" src="https://github.com/user-attachments/assets/15074bdf-560e-41d0-a8a8-f24797c7d1bd" />

Then we know that gs:15d00 is the address for current task struct, given that thread_info is its first member, at the same time flags is the first member of thread_info which is of 8 bytes, then the assembly that disables seccomp flag is as follows:

```
mov    rax, qword [gs:0x15d00];
and    qword [rax], 0xfffffffffffffeff;
```
Overall the exploit is in following shape:

```
_start:
  ...
  mov edi, 3
  lea rsi, [rel kernel_shellcode]  ; pointer to kernel shellcode
  mov edx, kernel_shellcode_len    ; length of kernel shellcode
  syscall                          ; write kernel shellcode to device

user_exp:
  ...                              ; exploit after kernel shellcode such as orw
  ...                              ; use flag_path flag_buf for data storage

kernel_shellcode:
  mov    rax, qword [gs:0x15d00];
  and    qword [rax], 0xfffffffffffffeff;
  ...                              ; perform commit_creds(prepare_kernel_cred(0))
  ret

flag_path: db "/flag", 0
flag_buf: times 256 db 0
kernel_shellcode_len equ $ - kernel_shellcode
```
## Level 9-10

<img width="623" height="366" alt="image" src="https://github.com/user-attachments/assets/a5ce9afb-bad2-4155-a61a-7d808b40539c" />

Looking at the module, basically an int64 array with 33 elements(264 bytes in total) is initialized and last 8 bytes is set to be printk address, then module takes in 264 bytes from user and tries to print it in kernel. Clearly that this address can be overwritten so that control flow may be hijacked to other functions, so one solution is to use function run_cmd in kernel that takes in a command and executes. Use similar approach of checking /proc/kallsyms to find its address. Then the exploit could be "/bin/chmod 777 /flag" + padding in between + addr of run_cmd.

For level 10 the logic is similar, but enabled kASLR. Notice that in kernel, last 21 bits are not randomized and fixed(compared with 12 for userspace). So to bypass this, instead of writing whole address obtained from symbol table, only write 5 nibbles(hex digits) and bruteforce the 16 possibilities for the 6th nibble from LSB, leaving rest of partial address unchanged.

## Level 11
Similar to level 8 of providing shellcode to kernel through a userspace binary, but this time the flag is loaded then deleted:
<img width="690" height="136" alt="image" src="https://github.com/user-attachments/assets/9520e5bb-8a57-4ed0-80a7-091b1bad04f0" />
<img width="442" height="364" alt="image" src="https://github.com/user-attachments/assets/876bc715-ad5d-479b-801d-638791ac211c" />
<img width="395" height="53" alt="image" src="https://github.com/user-attachments/assets/fa8cc041-b30a-4e21-9bc2-660e85e2b9f0" />

Therefore the solution is that inside the kernel shellcode, execute a python script that load the process memory (by fetching the process with "babykernel_xxx" to get pid, and load file /proc/pid/mem) through run_cmd. Notice that the flag is loaded to a certain address (0x404040) and this can be obtained through f.seek().

## Level 12
<img width="340" height="86" alt="image" src="https://github.com/user-attachments/assets/6e841b41-a21b-4732-ac10-fbdf4947aeef" />
The only difference compared with level 11 is that the child process containing flag is exited:
