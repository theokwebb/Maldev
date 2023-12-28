# LocalPayloadInjection.c

Payload is Msfvenom's calc x64 shellcode and is UUID obfuscated.

It is necessary to include `EXITFUNC=thread` in the Msfvenom command so that the shellcode terminates only the thread instead of the entire process after its spawns calc. I.e.:
`msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -f raw > payload.bin`

`UuidDeobfuscation` function was written by [@NUL0x4C]( https://github.com/NUL0x4C) and [@mrd0x]( https://github.com/mrd0x).
