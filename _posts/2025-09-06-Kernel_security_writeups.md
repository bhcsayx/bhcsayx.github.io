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

Level 1-4

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
