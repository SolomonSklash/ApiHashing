# ApiHashing: just a stable replacement, that is fast and efficient.

- no imported functions 
- easy to use
- compile time seed / string hashes (different hashes everybuild with no need to change anything)
- saves the module handle by hash, for the next possible api, so that it wont search for the module in peb, but by hash in our [map](https://github.com/ORCx41/ApiHashing/blob/main/ApiHashing/ApiHashing.cpp#L136)
- handles forwarded functions


# Example:
```
PVOID pVirtualAlloc = FastGetProcAddress(HASH(kernel32.dll), HASH(VirtualAlloc));
// kernel32.dll handle is now saved, so the next call wont go through the peb one more time ...
PVOID pVirtualProtect = FastGetProcAddress(HASH(kernel32.dll), HASH(VirtualProtect));

```

## Thanks for: 
- [rad9800](https://github.com/rad9800)
- [Cracked5pider](https://github.com/Cracked5pider)

