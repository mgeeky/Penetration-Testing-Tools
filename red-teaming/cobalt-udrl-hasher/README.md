## Cobalt Strike UDRL Hasher

Simple helper utility recomputing `DLL Reflective Loader` hashes, for offensive engineering needs whenever we want to recompile [User Defined Reflective Loaders](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_user-defined-rdll.htm) and such.

Ever came across [such hashes](https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.h#L43) before?

```
#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x534C0AB8

[...]

#define HASH_KEY						13
```

These can be used for a straightforward signaturing.

We can regenerate them easily with utility included here:

```
cmd> hash 55

#define KERNEL32DLL_HASH               0xA6154C3A       // kernel32.dll
#define NTDLLDLL_HASH                  0x0521447A       // ntdll.dll

#define LOADLIBRARYA_HASH              0xE0D79FEB       // LoadLibraryA
#define GETPROCADDRESS_HASH            0x6BAC2F89       // GetProcAddress
#define VIRTUALALLOC_HASH              0x9EE2D962       // VirtualAlloc
#define VIRTUALPROTECT_HASH            0x9154022F       // VirtualProtect
#define NTFLUSHINSTRUCTIONCACHE_HASH   0x7353E65D       // NtFlushInstructionCache

#define HASH_KEY                       55

```

**Notice** - if you want to get hash for a DLL, be sure to include its extension:

```
hash 55 kernel32.dll
```
