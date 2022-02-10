# HellsGate
 Rewrote Simple Process Injection using HellsGate in C# for fun and learning

```
.\HellsGate.exe <PID>
[+] Function Name: NtOpenProcess || Resolved Sycall no: 26
[+] Handle to process: 324
[+] Function Name: NtAllocateVirtualMemory || Resolved Sycall no: 18
[+] Pointer to the allocated buffer: 27F63DB0000
[+] Function Name: NtWriteVirtualMemory || Resolved Sycall no: 3A
[+] No of bytes written: 14B
[+] Function Name: NtCreateThreadEx || Resolved Sycall no: C1
[+] Newly created thread handle: 328
```

## Credits
* [Sektor7](https://twitter.com/SEKTOR7) 
* [Hellsgate implementation](https://github.com/am0nsec/HellsGate) by @Am0nsec and @RtlMateusz
* The community at GuidedHacking for the amazing blogpost on using [syscalls in C#](https://guidedhacking.com/threads/using-syscalls-in-c.12164/)
