# Kirby-Rust-Script-Patcher
Bypasses VMProtect packer, disables all server connections, and circumvents authentication and security checks by altering the control flow of the Rust script.

![Screenshot 2023-10-10 050505](https://github.com/nevioo1337/Kirby-Rust-Script-Patcher/assets/102999825/9a57eaa2-764e-47b4-b283-231194dbd9db)

## Usage
- Execute "Kirby Patcher.exe" and wait until it finishes.
- Enter some random shit when prompted to enter a license.
- !!! If you get any errors try again or change the delay in this file: "PatcherDelay_ms.cfg"(default=400ms) !!!

![Screenshot 2023-10-10 050013](https://github.com/nevioo1337/Kirby-Rust-Script-Patcher/assets/102999825/1f8d4c96-4a0a-4ee7-a8e9-b152e46db99a)
```
Init()
Hex: E8 3D D5 01 00
RVA: 0x6618E
call --> nop

IsBlacklisted()
Hex: E8 94 9B 01 00
RVA: 0x66857
call --> nop

IsBlacklisted
Hex: 0F 84 F2 03 00 00
RVA: 0x6686E
je --> jmp

CheckVersion()
Hex: E8 A9 34 02 00
RVA: 0x66DA2
call --> nop

CheckVersion
Hex: 72 34
RVA: 0x66DF1
jb --> jmp

Check()
Hex: 0F 84 5C 0A 00 00
RVA: 0x66E46
je --> jmp

AutoLogin()
Hex: E8 85 C8 01 00
RVA: 0x684F6
call --> nop

AutoLogin
Hex: 0F 84 71 1E 00 00
RVA: 0x68502
je --> nop

Login()
Hex: E8 CA A5 01 00
RVA: 0x6A7B1
call --> nop

Login
Hex: 0F 84 99 1D 00 00
RVA: 0x6A7BD
je --> nop

AuthCheck()
Hex: E8 F0 F6 01 00
RVA: 0x6568B
call --> nop

FailureExit()
Hex: FF D0
RVA: 0x65745
call --> nop
```
