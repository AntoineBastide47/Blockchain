#[cfg(test)]
mod tests {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    const EXPECTED_ISA_HASH: u64 = 10137370753225132244;

    fn fnv1a64(mut h: u64, bytes: &[u8]) -> u64 {
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

    macro_rules! hash_isa {
          (
              $( $(#[$doc:meta])* $name:ident = $opcode:expr, $mnemonic:literal => [ $( $field:ident : $kind:ident ),* $(,)? ], $gas:expr ),* $(,)?
          ) => {{
              let mut h = FNV_OFFSET;
              $(
                  h = fnv1a64(h, stringify!($name).as_bytes());
                  h = fnv1a64(h, &[crate::virtual_machine::isa::Instruction::$name as u8]);
                  h = fnv1a64(h, $mnemonic.as_bytes());
                  $( h = fnv1a64(h, stringify!($kind).as_bytes()); )*
                  h = fnv1a64(h, &($gas as u64).to_le_bytes());
              )*
              h = fnv1a64(h, b"Dispatch");
              h = fnv1a64(h, &[crate::virtual_machine::isa::Instruction::Dispatch as u8]);
              h = fnv1a64(h, b"DISPATCH");
              h = fnv1a64(h, &(crate::virtual_machine::isa::Instruction::Dispatch.base_gas()).to_le_bytes());
              h
          }};
      }

    fn current_isa_hash() -> u64 {
        crate::for_each_instruction!(hash_isa)
    }

    #[test]
    #[ignore]
    fn print_isa_hash() {
        println!("ISA_HASH=0x{:016x}", current_isa_hash());
    }

    #[test]
    fn isa_hash_unchanged() {
        assert_eq!(current_isa_hash(), EXPECTED_ISA_HASH);
    }
}
