[ init code ]
main:                            # Equivalent to a contract constructor
    LOAD_I64 r1, 5               # compute 5!
    CALL r2, factorial, 1, r1    # r2 now contains 120 (5!)
    CALL_HOST r2, "hash", 1, r2  # hash the value
    LOAD_STR r1, "hash"
    STORE_HASH r1, r2            # Store the hashes value at key "hash"
    HALT

[ runtime code ]
# factorial(n): computes n! iteratively
# input: r1 = n, output: r3 = n!
factorial:
    LOAD_I64 r3, 1              # result = 1
    LOAD_I64 r4, 1              # i = 1
    LOAD_I64 r5, 1              # increment
    fact_loop:
        MUL r3, r3, r4          # result *= i
        ADD r4, r4, r5          # i++
        BGE r1, r4, fact_loop   # while n >= i
    RET r3
