# Defender ACL Blocker
Disable Microsoft Defender user space part with simple ACL deny ACL

## Usage

### Regular build:
- install [Go](https://go.dev/dl/)
- clone this repo: `git clone https://github.com/lkarlslund/defender-acl-blocker`
- build it: `cd defender-acl-blocker && go build .`

### Obfuscated build:
- install [Go](https://go.dev/dl/)
- install Garble: `go install mvdan.cc/garble@latest`
- clone this repo: `git clone https://github.com/lkarlslund/defender-acl-blocker`
- build it: `cd defender-acl-blocker && garble -tiny -literals -seed=random build .`

### Run it:
From elevated command prompt:

```
defender-acl-blocker.exe
```

Reboot. Defender primary user mode service can not start anymore.

## How it works

The tool follows these steps to effectively block Defender (and other services) from starting:

1.  It enables `SeDebugPrivilege` to allow the process to interact with other system processes.
2.  It first impersonates the `SYSTEM` account by stealing a token from `winlogon.exe`.
    *   It then impersonates `TrustedInstaller`. If the service isn't running, it starts it, steals the token from the `trustedinstaller.exe` process, and assumes its identity. This provides the highest possible permissions over system files.
3.  It calculates the unique Service SID for each target service (e.g., `WinDefend`, `Sense`, `mpssvc`). Service SIDs are in the format `S-1-5-80-...` and are used to identify the service's identity in the local system.
4.  It retrieves the current Discretionary Access Control List (DACL) of a target system file (by default `C:\Windows\System32\kernel32.dll`).
    *   It prepends "DENY" Access Control Entries (ACEs) for each of the calculated Service SIDs to the ACL.
    *   It applies the modified ACL back to the target file.
5.  Because "Deny" ACEs take precedence over any "Allow" ACEs, the Windows Loader will refuse to load the target DLL (like `kernel32.dll`) when the service tries to start. Since almost every user-mode process requires `kernel32.dll`, the Defender services fail to initialize and start.

## Disclaimer

This tool is provided as-is, for educational purposes only, and is not supported by Microsoft, yada yada. Don't use it.
