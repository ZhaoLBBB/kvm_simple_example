.global _start
_start:
	xor %ecx, %ecx
	mov $0xa5a5, %ecx
	hlt
