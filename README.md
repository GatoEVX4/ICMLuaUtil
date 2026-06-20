# ICMLuaUtil

A small proof-of-concept for a Windows UAC bypass. It uses the elevated COM object behind `ICMLuaUtil` (CMSTPLUA, CLSID `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`) to run a command at high integrity without showing the consent prompt. Works when the current user is an admin and UAC is on its default setting.

> ⚠️ **Warning**: This tool demonstrates security vulnerabilities that could be exploited maliciously. Use responsibly and only in controlled environments.

## How it works

1. It calls `CoGetObject` with the `Elevation:Administrator!new:{CLSID}` moniker. That tells DCOM to auto-elevate the `CMSTPLUA` object instead of popping the consent dialog. This is intentional Windows behavior: a small list of COM servers are allowed to auto-elevate, and CMSTPLUA is one of them.
2. It treats the returned interface as `ICMLuaUtil` and calls vtable slot 9 (`ShellExec`) directly, no IDL or import lib needed, passing whatever command line was given on argv.
3. Before any of that, it patches its own PEB so the `ImagePathName` shows `explorer.exe` instead of the real path. Some AV/EDR check the caller's image name against the allowlist, so this is an old trick to slip past that check.
4. The strings it needs (the moniker, the `explorer.exe` path, the CLSID/IID bytes) are kept obfuscated and only decoded at runtime, so they don't sit in the binary as plain text.

## Credits

Found through the [UACMe](https://github.com/hfiref0x/UACME) repo by hfiref0x, the go-to collection of public UAC bypass techniques, where this exact method is listed as method 41.
