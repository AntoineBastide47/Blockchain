# ERC20-style token + Ownable mint
# Inspired by Solidity ERC20 (transfer/approve/transferFrom) and Ownable (owner/mint/transferOwnership)

__init__(3, r1):                                 # constructor: (name, symbol, initial_supply)
    STORE "name", r1
    STORE "symbol", r2
    STORE "total_supply", r3

    CALL_HOST r4, "caller", 0, r0         # deployer becomes owner
    STORE "owner", r4

    MOVE r1, r4
    CALL r5, balance_key, 1, r1           # balances[owner] = initial_supply
    STORE r5, r3

    HALT

# -------------------------
# Internal helpers
# -------------------------

# balance_key(addr) -> key
# key = hash("bal", addr)
balance_key(1, r1):
    MOVE r2, "bal"
    MOVE r3, r1
    SHA3 r4, 2, r2           # argv=r2 => [r2,r3]
    RET r4

# allow_key(owner, spender) -> key
# key = hash("allow", owner, spender)
allow_key(2, r1):                         # r1=owner, r2=spender
    MOVE r3, "allow"
    MOVE r4, r1
    MOVE r5, r2
    SHA3 r6, 3, r3           # argv=r3 => [r3,r4,r5]
    RET r6

# load_i64_or_zero(key) -> i64
load_i64_or_zero(1, r1):                  # r1=key
    HAS_STATE r2, r1
    BEQ r2, 0, __liz_zero
    LOAD_I64 r3, r1
    RET r3
__liz_zero:
    MOVE r3, 0
    RET r3

# require_owner() -> bool (0/1)
require_owner:
    CALL_HOST r1, "caller", 0, r0
    LOAD_STR  r2, "owner"
    EQ r3, r1, r2
    RET r3

# -------------------------
# Metadata / views
# -------------------------

pub name:
    LOAD_STR r1, "name"
    RET r1

pub symbol:
    LOAD_STR r1, "symbol"
    RET r1

pub owner:
    LOAD_STR r1, "owner"
    RET r1

pub total_supply:
    LOAD_I64 r1, "total_supply"
    RET r1

pub balance_of(1, r1):                    # r1=addr
    CALL r2, balance_key, 1, r1
    MOVE r1, r2
    CALL r3, load_i64_or_zero, 1, r1
    RET r3

pub allowance(2, r1):                     # r1=owner, r2=spender
    CALL  r3, allow_key, 2, r1            # argv=r1 => [r1,r2]
    MOVE r1, r3
    CALL r4, load_i64_or_zero, 1, r1
    RET r4

# -------------------------
# ERC20 core
# -------------------------

pub transfer(2, r1):                      # r1=to, r2=amount
    LT  r3, r2, 0                         # reject negative
    BNE r3, 0, __t_fail

    CALL_HOST r4, "caller", 0, r0         # from

    MOVE r1, r4
    CALL r5, balance_key, 1, r1           # from_key
    MOVE r1, r5
    CALL r6, load_i64_or_zero, 1, r1      # from_bal

    GE  r7, r6, r2                        # from_bal >= amount
    BEQ r7, 0, __t_fail

    SUB r6, r6, r2
    STORE r5, r6                          # balances[from] -= amount

    CALL r8, balance_key, 1, r1           # to_key
    MOVE r1, r8
    CALL r9, load_i64_or_zero, 1, r1      # to_bal
    ADD r9, r9, r2
    STORE r8, r9                          # balances[to] += amount

    MOVE r10, 1
    RET r10
__t_fail:
    MOVE r10, 0
    RET r10

pub approve(2, r1):                       # r1=spender, r2=amount
    LT  r3, r2, 0
    BNE r3, 0, __a_fail

    CALL_HOST r4, "caller", 0, r0         # owner = caller

    MOVE r5, r4                           # argv for allow_key: [owner, spender]
    MOVE r6, r1
    MOVE r1, r5
    MOVE r2, r6
    CALL r7, allow_key, 2, r1             # allow_key(owner, spender)

    STORE r7, r2                          # allowances[owner][spender] = amount

    MOVE r10, 1
    RET r10
__a_fail:
    MOVE r10, 0
    RET r10

pub transfer_from(3, r1):                 # r1=from, r2=to, r3=amount
    LT  r4, r3, 0
    BNE r4, 0, __tf_fail

    CALL_HOST r5, "caller", 0, r0         # spender = caller
    MOVE r17, r2                          # save 'to'

    # allowance = allowances[from][spender]
    MOVE r6, r1
    MOVE r7, r5
    MOVE r1, r6
    MOVE r2, r7
    CALL r8, allow_key, 2, r1
    MOVE r1, r8
    CALL r9, load_i64_or_zero, 1, r1

    GE  r10, r9, r3
    BEQ r10, 0, __tf_fail

    # from balance
    CALL r11, balance_key, 1, r1
    MOVE r1, r11
    CALL r12, load_i64_or_zero, 1, r1
    GE  r13, r12, r3
    BEQ r13, 0, __tf_fail

    # balances[from] -= amount
    SUB r12, r12, r3
    STORE r11, r12

    # balances[to] += amount
    MOVE r1, r17
    CALL r14, balance_key, 1, r1
    MOVE r1, r14
    CALL r15, load_i64_or_zero, 1, r1
    ADD r15, r15, r3
    STORE r14, r15

    # allowances[from][spender] -= amount
    SUB r9, r9, r3
    STORE r8, r9

    MOVE r16, 1
    RET r16
__tf_fail:
    MOVE r16, 0
    RET r16

# -------------------------
# Ownable extensions
# -------------------------

pub mint(2, r1):                          # r1=to, r2=amount (owner only)
    CALL r3, require_owner, 0, r0
    BEQ  r3, 0, __m_fail

    LT  r4, r2, 0
    BNE r4, 0, __m_fail

    LOAD_I64 r5, "total_supply"
    ADD r5, r5, r2
    STORE "total_supply", r5

    CALL r6, balance_key, 1, r1
    MOVE r1, r6
    CALL r7, load_i64_or_zero, 1, r1
    ADD r7, r7, r2
    STORE r6, r7

    MOVE r8, 1
    RET r8
__m_fail:
    MOVE r8, 0
    RET r8

pub transfer_ownership(1, r1):            # r1=new_owner (owner only)
    CALL r2, require_owner, 0, r0
    BEQ  r2, 0, __to_fail

    STORE "owner", r1

    MOVE r3, 1
    RET r3
__to_fail:
    MOVE r3, 0
    RET r3
