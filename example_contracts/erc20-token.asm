# ERC20-style token + Ownable mint
# Inspired by Solidity ERC20 (transfer/approve/transferFrom) and Ownable (owner/mint/transferOwnership)
#
# Calling convention: functions return results in registers documented per function.
# Callers must save any registers they need before calling.

__init__(3, r1):                                 # constructor: (name, symbol, initial_supply)
    STORE "name", r1
    STORE "symbol", r2
    STORE "total_supply", r3

    CALL_HOST r4, "caller", 0, r0         # deployer becomes owner
    STORE "owner", r4

    MOVE r1, r4
    CALL balance_key                      # r50 = balance key for owner
    STORE r50, r3

    HALT

# -------------------------
# Internal helpers
# -------------------------

# balance_key(r1=addr) -> r50=key
# key = hash("bal", addr)
balance_key(1, r1):
    MOVE r48, "bal"
    MOVE r49, r1
    SHA3 r50, 2, r48           # argv=r48 => [r48,r49]
    RET

# allow_key(r1=owner, r2=spender) -> r50=key
# key = hash("allow", owner, spender)
allow_key(2, r1):
    MOVE r48, "allow"
    MOVE r49, r1
    MOVE r47, r2
    SHA3 r50, 3, r48           # argv=r48 => [r48,r49,r47]
    RET

# load_i64_or_zero(r1=key) -> r51=value
load_i64_or_zero(1, r1):
    HAS_STATE r2, r1
    BEQ r2, 0, __liz_zero
    LOAD_I64 r51, r1
    RET
__liz_zero:
    MOVE r51, 0
    RET

# require_owner() -> r52=bool (0/1)
require_owner:
    CALL_HOST r1, "caller", 0, r0
    LOAD_STR  r2, "owner"
    EQ r52, r1, r2
    RET

# -------------------------
# Metadata / views
# -------------------------

pub name:
    LOAD_STR r1, "name"
    RET

pub symbol:
    LOAD_STR r1, "symbol"
    RET

pub owner:
    LOAD_STR r1, "owner"
    RET

pub total_supply:
    LOAD_I64 r1, "total_supply"
    RET

pub balance_of(1, r1):                    # r1=addr
    CALL balance_key                      # r50 = key
    MOVE r1, r50
    CALL load_i64_or_zero                 # r51 = balance
    MOVE r1, r51
    RET

pub allowance(2, r1):                     # r1=owner, r2=spender
    CALL allow_key                        # r50 = key
    MOVE r1, r50
    CALL load_i64_or_zero                 # r51 = allowance
    MOVE r1, r51
    RET

# -------------------------
# ERC20 core
# -------------------------

pub transfer(2, r1):                      # r1=to, r2=amount
    LT  r3, r2, 0                         # reject negative
    BNE r3, 0, __t_fail

    MOVE r20, r1                          # save 'to'
    MOVE r21, r2                          # save 'amount'

    CALL_HOST r4, "caller", 0, r0         # from

    MOVE r1, r4
    CALL balance_key                      # r50 = from_key
    MOVE r22, r50                         # save from_key
    MOVE r1, r50
    CALL load_i64_or_zero                 # r51 = from_bal

    GE  r7, r51, r21                      # from_bal >= amount
    BEQ r7, 0, __t_fail

    SUB r51, r51, r21
    STORE r22, r51                        # balances[from] -= amount

    MOVE r1, r20
    CALL balance_key                      # r50 = to_key
    MOVE r23, r50                         # save to_key
    MOVE r1, r50
    CALL load_i64_or_zero                 # r51 = to_bal
    ADD r51, r51, r21
    STORE r23, r51                        # balances[to] += amount

    MOVE r10, 1
    RET
__t_fail:
    MOVE r10, 0
    RET

pub approve(2, r1):                       # r1=spender, r2=amount
    LT  r3, r2, 0
    BNE r3, 0, __a_fail

    MOVE r20, r2                          # save amount

    CALL_HOST r4, "caller", 0, r0         # owner = caller

    MOVE r1, r4                           # r1=owner, r2=spender (r2 still set from args)
    CALL allow_key                        # r50 = allow_key(owner, spender)

    STORE r50, r20                        # allowances[owner][spender] = amount

    MOVE r10, 1
    RET
__a_fail:
    MOVE r10, 0
    RET

pub transfer_from(3, r1):                 # r1=from, r2=to, r3=amount
    LT  r4, r3, 0
    BNE r4, 0, __tf_fail

    MOVE r20, r1                          # save 'from'
    MOVE r21, r2                          # save 'to'
    MOVE r22, r3                          # save 'amount'

    CALL_HOST r5, "caller", 0, r0         # spender = caller

    # allowance = allowances[from][spender]
    MOVE r1, r20
    MOVE r2, r5
    CALL allow_key                        # r50 = allow key
    MOVE r23, r50                         # save allow_key
    MOVE r1, r50
    CALL load_i64_or_zero                 # r51 = allowance
    MOVE r24, r51                         # save allowance

    GE  r10, r24, r22
    BEQ r10, 0, __tf_fail

    # from balance
    MOVE r1, r20
    CALL balance_key                      # r50 = from balance key
    MOVE r25, r50                         # save from_key
    MOVE r1, r50
    CALL load_i64_or_zero                 # r51 = from_bal
    GE  r13, r51, r22
    BEQ r13, 0, __tf_fail

    # balances[from] -= amount
    SUB r51, r51, r22
    STORE r25, r51

    # balances[to] += amount
    MOVE r1, r21
    CALL balance_key                      # r50 = to balance key
    MOVE r26, r50                         # save to_key
    MOVE r1, r50
    CALL load_i64_or_zero                 # r51 = to_bal
    ADD r51, r51, r22
    STORE r26, r51

    # allowances[from][spender] -= amount
    SUB r24, r24, r22
    STORE r23, r24

    MOVE r16, 1
    RET
__tf_fail:
    MOVE r16, 0
    RET

# -------------------------
# Ownable extensions
# -------------------------

pub mint(2, r1):                          # r1=to, r2=amount (owner only)
    MOVE r20, r1                          # save 'to'
    MOVE r21, r2                          # save 'amount'

    CALL require_owner                    # r52 = is_owner
    BEQ  r52, 0, __m_fail

    LT  r4, r21, 0
    BNE r4, 0, __m_fail

    LOAD_I64 r5, "total_supply"
    ADD r5, r5, r21
    STORE "total_supply", r5

    MOVE r1, r20
    CALL balance_key                      # r50 = key
    MOVE r1, r50
    CALL load_i64_or_zero                 # r51 = bal
    ADD r51, r51, r21
    STORE r50, r51

    MOVE r8, 1
    RET
__m_fail:
    MOVE r8, 0
    RET

pub transfer_ownership(1, r1):            # r1=new_owner (owner only)
    MOVE r20, r1                          # save new_owner

    CALL require_owner                    # r52 = is_owner
    BEQ  r52, 0, __to_fail

    STORE "owner", r20

    MOVE r3, 1
    RET
__to_fail:
    MOVE r3, 0
    RET
