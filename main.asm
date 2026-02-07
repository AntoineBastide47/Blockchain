[ init code ]
main:                            # Equivalent to a contract constructor
    MOVE r1, 5                   # compute 5!
    CALL1 r2, factorial, r1      # r2 now contains 120 (5!)
    CALL_HOST1 r2, "hash", r2    # hash the value
    STORE "hash", r2             # Store the hashes value at key "hash"
    HALT

[ runtime code ]
# factorial(n): computes n! iteratively
# input: r1 = n, output: r3 = n!
pub factorial(1, r1):
    INC r3                      # result = 1
    __fact_loop:                # prefixed with __ to indicate internal label
        MUL r3, r3, r1          # result *= i
        DEC r1                  # i--
        BGEI r1, 1, __fact_loop # while n >= 1
    RET r3
