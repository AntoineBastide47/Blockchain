//! Static checks for ISA stability.
//!
//! These tests ensure that instruction definitions (opcodes, mnemonics, gas costs)
//! remain unchanged across updates. Any modification to the ISA will cause these
//! tests to fail, providing a safety net against accidental changes.

use crate::for_each_instruction;

macro_rules! define_static_checks {
    (
        $(
            $(#[$doc:meta])*
            $name:ident = $opcode:expr, $mnemonic:literal => [
                $( $field:ident : $kind:ident ),* $(,)?
            ], $gas:expr
        ),* $(,)?
    ) => {
        #[cfg(test)]
        mod tests {
            use crate::virtual_machine::isa::Instruction;

            const INSTRUCTIONS: &[(Instruction, u8, &str, u64)] = &[
                $( (Instruction::$name, $opcode, $mnemonic, $gas), )*
            ];
            /*
            To update this hash after intentional ISA changes, run:
            `python3 - <<'PY'
            import re
            from pathlib import Path
            text = Path("src/virtual_machine/isa.rs").read_text()
            pattern = re.compile(r'^\\s*([A-Za-z0-9_]+)\\s*=\\s*(0x[0-9A-Fa-f]+),\\s*\"([^\"]+)\"\\s*=>\\s*\\[[^\\]]*\\],\\s*([0-9]+)\\s*,?\\s*$', re.MULTILINE)
            entries = pattern.findall(text)
            FNV_OFFSET = 14695981039346656037
            FNV_PRIME = 1099511628211
            h = FNV_OFFSET
            def fnv_update(h, b):
                return (h ^ b) * FNV_PRIME & 0xFFFFFFFFFFFFFFFF
            for name, op_hex, mnemonic, gas in entries:
                opcode = int(op_hex, 16)
                h = fnv_update(h, opcode & 0xFF)
                for b in mnemonic.encode("utf-8"):
                    h = fnv_update(h, b)
                h = fnv_update(h, 0)
                gas_val = int(gas)
                for b in gas_val.to_bytes(8, "little"):
                    h = fnv_update(h, b)
            h = fnv_update(h, 0xFF)
            for b in b"DISPATCH":
                h = fnv_update(h, b)
            h = fnv_update(h, 0)
            for b in (10).to_bytes(8, "little"):
                h = fnv_update(h, b)
            print(h)
            PY`
            */
            const EXPECTED_ISA_HASH: u64 = 6_222_320_695_447_808_144;

            fn fnv1a_hash(bytes: &[u8], mut hash: u64) -> u64 {
                const FNV_PRIME: u64 = 1_099_511_628_211;
                for b in bytes {
                    hash ^= *b as u64;
                    hash = hash.wrapping_mul(FNV_PRIME);
                }
                hash
            }

            fn isa_hash() -> u64 {
                const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
                let mut hash = FNV_OFFSET;
                for (_instr, opcode, mnemonic, gas) in INSTRUCTIONS {
                    hash = fnv1a_hash(&[*opcode], hash);
                    hash = fnv1a_hash(mnemonic.as_bytes(), hash);
                    hash = fnv1a_hash(&[0], hash);
                    hash = fnv1a_hash(&gas.to_le_bytes(), hash);
                }

                // Include the special Dispatch instruction.
                hash = fnv1a_hash(&[0xFF], hash);
                hash = fnv1a_hash(b"DISPATCH", hash);
                hash = fnv1a_hash(&[0], hash);
                hash = fnv1a_hash(&10_u64.to_le_bytes(), hash);
                hash
            }

            /// Verifies the ISA definition hash has not changed.
            #[test]
            fn instruction_definition_hash_unchanged() {
                assert_eq!(
                    isa_hash(),
                    EXPECTED_ISA_HASH,
                    "ISA definition changed; update EXPECTED_ISA_HASH if intentional"
                );
            }
        }
    };
}

for_each_instruction!(define_static_checks);
