---
title: 'Kernel Security'
date: 2025-09-06
permalink: /posts/2025/09/kernel-security/
tags:
  - Linux Kernel
  - CTF
  - pwn college
---

This is a series of writeups to introductory Linux Kernel security challenges on <https://pwn.college>. Since platform policy does not want full solutions get leaked so just core ideas and a few snippets(not full exploits) are provided.

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
