---
title: 'Kernel Security'
date: 2025-09-06
permalink: /posts/2025/09/kernel-security/
tags:
  - Linux Kernel
  - CTF
  - pwn college
---

This is a series of writeups to introductory Linux Kernel security challenges on <[kernel-security](https://pwn.college/system-security/kernel-security/)>. Since platform policy does not want full solutions get leaked so just core ideas and a few snippets(not full exploits) are provided.

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

In short, to disable the seccomp
