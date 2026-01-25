[ init code ]
main:                            # Equivalent to a contract constructor
    MOVE r1, 5                   # compute 5!
    CALL r2, factorial, 1, r1    # r2 now contains 120 (5!)
    CALL_HOST r2, "hash", 1, r2  # hash the value
    STORE_HASH "hash", r2        # Store the hashes value at key "hash"
    HALT

[ runtime code ]
# factorial(n): computes n! iteratively
# input: r1 = n, output: r3 = n!
pub factorial:
    MOVE r3, 1                  # result = 1
    fact_loop:
        MUL r3, r3, r1          # result *= i
        SUB r1, r1, 1           # i--
        BGE r1, 1, fact_loop    # while n >= 1
    RET r3
