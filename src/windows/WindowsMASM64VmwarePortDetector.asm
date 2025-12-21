;---MASM 64bit native protected mode 
TITLE VMware Port Checking Procedure (vmpd64.asm)
 asmvmwarepd PROTO C
 .data
 .code 
 asmvmwarepd PROC 

	true = 1
	false = 0
	mov    eax,		564D5868h
	mov    ebx,		0
	mov    ecx,		10
	mov    edx,		5658h
    in     eax,		dx			;might cause SISEGV/exception on baremetal!!!!
    
    cmp    ebx, 564D5868h 
    je returnTrue
    
returnFalse:
	mov al,false
	jmp short exit
	
returnTrue:
	mov al, true
	
exit:
	ret
    
 asmvmwarepd ENDP 
 END