__init__:                         # Contract constructor
    CALL1 r2, factorial, 5        # r2 = 5! = 120
    CALL_HOST1 r2, "hash", r2     # hash the value
    STORE "hash", r2              # Store the hashes value at key "hash"
    HALT

# factorial(n): computes n! iteratively
# input: r1 = n, output: r3 = n!
pub factorial(1, r1):
    INC r3                        # result = 1
    __fact_loop:                  # prefixed with __ to indicate non function label to skip parsing
        MUL r3, r3, r1            # result *= i
        DEC r1                    # i--
        BGE r1, 1, __fact_loop    # while n >= 1
    RET r3
