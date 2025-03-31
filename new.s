    .text
    .globl _start

_start:
    # Initialize stack pointer
    la a0, stack_top      # Load the top of stack address into a0
    addi sp, a0, 0        # Set the stack pointer

    # Call main function
    jal main

    # Exit
    li a7, 93             # Exit system call
    ecall

main:
    # Set up registers
    li t0, 100            # Set t0 = 100
    li t1, 0              # Set t1 = 0
    li t2, 0              # Set t2 = 0

    # Loop 1: Decrement t0 until it's 0
loop1:
    bnez t0, loop1_body   # If t0 != 0, jump to loop1_body
    j loop1_end

loop1_body:
    addi t0, t0, -1       # Decrement t0 by 1
    addi t1, t1, 2        # Increment t1 by 2
    addi t2, t2, 3        # Increment t2 by 3
    j loop1               # Jump back to the start of loop1

loop1_end:
    # Print result after loop1 ends
    li a7, 64             # Syscall for printing (write)
    li a0, 1              # File descriptor 1 (stdout)
    mv a1, t1             # Move t1 value to a1 for printing
    ecall

    # Loop 2: Fibonacci sequence
    li t3, 0              # Fibonacci sequence initializer
    li t4, 1              # Fibonacci sequence initializer
    li t5, 10             # Number of Fibonacci numbers to print

loop2:
    bge t5, 0, loop2_body # If t5 >= 0, jump to loop2_body
    j loop2_end

loop2_body:
    add t6, t3, t4        # t6 = t3 + t4
    mv t3, t4             # t3 = t4
    mv t4, t6             # t4 = t6
    addi t5, t5, -1       # Decrement t5
    mv a0, t6             # Move the Fibonacci number to a0 for printing
    li a7, 64             # Syscall for printing (write)
    li a1, 1              # File descriptor 1 (stdout)
    ecall
    j loop2               # Repeat the loop

loop2_end:
    # Exit the program
    li a7, 93             # Exit syscall
    ecall

    .data
stack_top: .word 0x10000000  # Stack top address (example address)
