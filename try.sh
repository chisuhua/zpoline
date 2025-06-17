#echo 'stp x29, x30, [sp, #-16]!' > test.s
echo 'blr x7' > test.s
#echo 'nop' > test.s
echo "sub sp, sp, #0x80" >> test.s
echo "mov x29, #0x4" >> test.s
echo "movk x29, #0x3456, LSL #16" >> test.s
echo "movk x29, #0x1234, LSL #32" >> test.s
echo "movk x29, #0x12,   LSL #48" >> test.s
echo "br x29" >> test.s
echo "stp x29, x30, [sp, #-16]!" >> test.s
echo "lsl x29, x8, #2 " >> test.s
echo "blr x29" >> test.s
echo "ret" >> test.s
echo "br x7" >> test.s

aarch64-linux-gnu-as -o test.o test.s
objdump -d test.o
