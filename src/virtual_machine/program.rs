//! Bytecode program representation and serialization.
//!
//! [`DeployProgram`] bundles compiled bytecode with its associated string pool
//! for contract deployment. [`ExecuteProgram`] encodes a function call into a
//! deployed contract with typed arguments.

use crate::types::bytes::Bytes;
use crate::types::encoding::{Decode, Encode};
use crate::types::hash::Hash;
use crate::virtual_machine::errors::VMError;
use crate::virtual_machine::vm::Value;
use blockchain_derive::BinaryCodec;

/// Magic bytes identifying a serialized VM program.
const MAGIC: &[u8; 5] = b"VM_BC";

/// Current bytecode format version.
const CURRENT_VERSION: Version = Version::new(0, 4, 0);

/// Semantic version for bytecode format compatibility.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, BinaryCodec)]
struct Version {
    major: u8,
    minor: u8,
    patch: u8,
}

impl Version {
    /// Creates a new version with the given components.
    const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

/// Compiled bytecode program with its string pool and labels.
///
/// Contains all data needed to execute a program: the raw bytecode,
/// string literals referenced by string operands, and label definitions
/// mapping names to bytecode offsets.
#[derive(Debug, Clone, BinaryCodec)]
pub struct DeployProgram {
    /// Compiled initialization instruction bytecode.
    pub init_code: Vec<u8>,
    /// Compiled runtime instruction bytecode.
    pub runtime_code: Vec<u8>,
    /// Interned string literals referenced by index.
    pub items: Vec<Vec<u8>>,
}

impl DeployProgram {
    /// Serializes the program to a portable binary format.
    ///
    /// The output includes a magic header and version for compatibility checking.
    pub fn to_bytes(&self) -> Bytes {
        let mut out = Vec::new();
        MAGIC.encode(&mut out);
        CURRENT_VERSION.encode(&mut out);
        b"DEPLOY_PROGRAM".to_vec().encode(&mut out);
        self.encode(&mut out);
        Bytes::from_vec(out)
    }

    /// Deserializes a program from its binary representation.
    ///
    /// Validates the magic header and version, rejecting programs from
    /// newer (incompatible) bytecode formats.
    pub fn from_bytes(mut input: &[u8]) -> Result<Self, VMError> {
        if input.len() < MAGIC.len() {
            return Err(VMError::DecodeError {
                reason: "truncated".to_string(),
            });
        }

        if &<[u8; 5]>::decode(&mut input)? != MAGIC {
            return Err(VMError::DecodeError {
                reason: "bad magic".to_string(),
            });
        }

        if Version::decode(&mut input)? != CURRENT_VERSION {
            return Err(VMError::DecodeError {
                reason: "unsupported version".to_string(),
            });
        }

        if Vec::<u8>::decode(&mut input)?.as_slice() != b"DEPLOY_PROGRAM" {
            return Err(VMError::DecodeError {
                reason: "bad prefix".to_string(),
            });
        }

        let p = DeployProgram::decode(&mut input)?;
        if !input.is_empty() {
            return Err(VMError::DecodeError {
                reason: "trailing bytes".to_string(),
            });
        }
        Ok(p)
    }
}

/// Program payload used to invoke a deployed contract.
///
/// Stores typed arguments as [`Value`]s plus a heap section (`arg_items`) for any
/// referenced strings or hashes. Value::Ref indices refer to `arg_items` slots.
#[derive(Debug, Clone, BinaryCodec)]
pub struct ExecuteProgram {
    /// Hash identifying the target contract account.
    pub contract_id: Hash,
    /// Index of the public entry point to invoke (maps to dispatcher selector).
    pub function_id: i64,
    /// Arguments as VM Values. `Value::Ref` indices refer to `arg_items`.
    pub args: Vec<Value>,
    /// Heap items for argument refs (`Value::Ref`).
    pub arg_items: Vec<Vec<u8>>,
}

impl ExecuteProgram {
    /// Serializes the program to a portable binary format.
    ///
    /// The output includes a magic header and version for compatibility checking.
    pub fn to_bytes(&self) -> Bytes {
        let mut out = Vec::new();
        MAGIC.encode(&mut out);
        CURRENT_VERSION.encode(&mut out);
        b"EXECUTE_PROGRAM".to_vec().encode(&mut out);
        self.encode(&mut out);
        Bytes::from_vec(out)
    }

    /// Deserializes a program from its binary representation.
    ///
    /// Validates the magic header and version, rejecting programs from
    /// newer (incompatible) bytecode formats.
    pub fn from_bytes(mut input: &[u8]) -> Result<Self, VMError> {
        if input.len() < MAGIC.len() {
            return Err(VMError::DecodeError {
                reason: "truncated".to_string(),
            });
        }

        if &<[u8; 5]>::decode(&mut input)? != MAGIC {
            return Err(VMError::DecodeError {
                reason: "bad magic".to_string(),
            });
        }

        if Version::decode(&mut input)? != CURRENT_VERSION {
            return Err(VMError::DecodeError {
                reason: "unsupported version".to_string(),
            });
        }

        if Vec::<u8>::decode(&mut input)?.as_slice() != b"EXECUTE_PROGRAM" {
            return Err(VMError::DecodeError {
                reason: "bad prefix".to_string(),
            });
        }

        let p = ExecuteProgram::decode(&mut input)?;
        if !input.is_empty() {
            return Err(VMError::DecodeError {
                reason: "trailing bytes".to_string(),
            });
        }
        Ok(p)
    }

    /// Creates an `ExecuteProgram` targeting the given contract and function.
    pub fn new(
        contract_id: Hash,
        function_id: i64,
        args: Vec<Value>,
        arg_items: Vec<Vec<u8>>,
    ) -> ExecuteProgram {
        Self {
            contract_id,
            function_id,
            args,
            arg_items,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::virtual_machine::assembler::assemble_source;
    use crate::virtual_machine::isa::Instruction;
    use crate::virtual_machine::vm::Value;

    impl DeployProgram {
        /// Creates a new program from pre-assembled components.
        pub(crate) fn new(strings: Vec<Vec<u8>>, bytecode: Vec<u8>) -> DeployProgram {
            Self {
                items: strings,
                init_code: Vec::new(),
                runtime_code: bytecode,
            }
        }
    }

    #[test]
    fn roundtrip_empty_program() {
        let program = DeployProgram::new(vec![], vec![]);
        let bytes = program.to_bytes();
        let decoded = DeployProgram::from_bytes(&bytes).unwrap();
        assert!(decoded.items.is_empty());
        assert!(decoded.runtime_code.is_empty());
    }

    #[test]
    fn roundtrip_with_bytecode() {
        let program = DeployProgram::new(vec![], vec![0x00, 0x01, 0x02]);
        let bytes = program.to_bytes();
        let decoded = DeployProgram::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.runtime_code, vec![0x00, 0x01, 0x02]);
    }

    #[test]
    fn roundtrip_with_strings() {
        let program = DeployProgram::new(vec!["hello".into(), "world".into()], vec![0x01, 0x00]);
        let bytes = program.to_bytes();
        let decoded = DeployProgram::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.items, vec![b"hello", b"world"]);
        assert_eq!(decoded.runtime_code, vec![0x01, 0x00]);
    }

    #[test]
    fn from_bytes_truncated() {
        let err = DeployProgram::from_bytes(&[0x00, 0x01]).unwrap_err();
        assert!(matches!(err, VMError::DecodeError{ref reason} if reason == "truncated"));
    }

    #[test]
    fn from_bytes_bad_magic() {
        let err = DeployProgram::from_bytes(b"BADMA\x00\x02\x00").unwrap_err();
        assert!(matches!(err, VMError::DecodeError{ref reason} if reason == "bad magic"));
    }

    #[test]
    fn from_bytes_unsupported_version() {
        let mut bytes = Vec::new();
        MAGIC.encode(&mut bytes);
        Version::new(255, 0, 0).encode(&mut bytes);
        let err = DeployProgram::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, VMError::DecodeError{ref reason} if reason == "unsupported version"));
    }

    #[test]
    fn from_bytes_trailing_bytes() {
        let program = DeployProgram::new(vec![], vec![]);
        let mut bytes = program.to_bytes().to_vec();
        bytes.push(0xFF);
        let err = DeployProgram::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, VMError::DecodeError{ref reason} if reason == "trailing bytes"));
    }

    #[test]
    fn execute_roundtrip_empty_args() {
        let program = ExecuteProgram::new(Hash::zero(), 7, vec![], vec![]);
        let bytes = program.to_bytes();
        let decoded = ExecuteProgram::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.contract_id, Hash::zero());
        assert_eq!(decoded.function_id, 7);
        assert!(decoded.args.is_empty());
        assert!(decoded.arg_items.is_empty());
    }

    #[test]
    fn execute_roundtrip_with_args() {
        let args = vec![Value::Int(1), Value::Bool(true)];
        let program = ExecuteProgram::new(Hash::zero(), 42, args.clone(), vec![]);
        let bytes = program.to_bytes();
        let decoded = ExecuteProgram::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.contract_id, Hash::zero());
        assert_eq!(decoded.function_id, 42);
        assert_eq!(decoded.args, args);
        assert!(decoded.arg_items.is_empty());
    }

    #[test]
    fn execute_roundtrip_with_arg_items_and_refs() {
        let arg_items = vec![b"hello".to_vec(), b"hashbytes".to_vec()];
        let args = vec![
            Value::Ref(0),
            Value::Ref(1),
            Value::Int(7),
            Value::Bool(false),
        ];
        let program = ExecuteProgram::new(Hash::zero(), 9, args.clone(), arg_items.clone());
        let bytes = program.to_bytes();
        let decoded = ExecuteProgram::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.contract_id, Hash::zero());
        assert_eq!(decoded.function_id, 9);
        assert_eq!(decoded.args, args);
        assert_eq!(decoded.arg_items, arg_items);
    }

    #[test]
    fn dispatcher_uses_dispatch_opcode() {
        // Two public functions -> single DISPATCH instruction with 2 entries.
        // DISPATCH: opcode(1) + count(1) + 2 * (offset_i32(4) + argr(1)) = 12 bytes
        let source = r#"
[ runtime code ]
pub foo:
    HALT
pub bar:
    HALT
"#;
        let program = assemble_source(source).unwrap();
        let bc = &program.runtime_code;

        // DISPATCH opcode
        assert_eq!(bc[0], Instruction::Dispatch as u8);
        // count = 2
        assert_eq!(bc[1], 2);

        // Function bodies after the DISPATCH instruction (12 bytes)
        assert_eq!(bc[12], Instruction::Halt as u8); // bar (sorted first)
        assert_eq!(bc[13], Instruction::Halt as u8); // foo

        assert_eq!(bc.len(), 14);
    }

    #[test]
    fn dispatcher_skips_when_no_public_labels() {
        let source = r#"
[ runtime code ]
foo:
    HALT
"#;
        let program = assemble_source(source).unwrap();
        let bc = &program.runtime_code;

        // No dispatcher injected; only the user HALT remains.
        assert_eq!(bc.len(), 1);
        assert_eq!(bc[0], Instruction::Halt as u8);
    }

    #[test]
    fn dispatcher_single_entry() {
        // Single public function -> DISPATCH with 1 entry.
        // DISPATCH: opcode(1) + count(1) + 1 * (offset_i32(4) + argr(1)) = 7 bytes
        let source = r#"
[ runtime code ]
pub only:
    HALT
"#;
        let program = assemble_source(source).unwrap();
        let bc = &program.runtime_code;

        assert_eq!(bc[0], Instruction::Dispatch as u8);
        assert_eq!(bc[1], 1); // count

        // Function body after DISPATCH (7 bytes)
        assert_eq!(bc[7], Instruction::Halt as u8);
        assert_eq!(bc.len(), 8);
    }

    #[test]
    fn dispatcher_sorts_public_labels_for_entries() {
        // Source order is z then a; entries should be sorted alphabetically (a, z).
        // DISPATCH: opcode(1) + count(1) + 2 * (offset_i32(4) + argr(1)) = 12 bytes
        let source = r#"
[ runtime code ]
pub zebra:
    HALT
pub alpha:
    HALT
"#;
        let program = assemble_source(source).unwrap();
        let bc = &program.runtime_code;

        assert_eq!(bc[0], Instruction::Dispatch as u8);
        assert_eq!(bc[1], 2); // count

        // Entry 0 = alpha (sorted first), entry 1 = zebra
        // Each entry: offset_i32(4) + argr(1) = 5 bytes, starting at byte 2
        let entry0_offset = i32::from_le_bytes(bc[2..6].try_into().unwrap());
        let entry1_offset = i32::from_le_bytes(bc[7..11].try_into().unwrap());

        // Bodies: alpha at 13 (second HALT, source order: zebra=12, alpha=13)
        // Offsets are PC-relative from end of DISPATCH (byte 12)
        assert_eq!(entry0_offset, 1); // alpha body at 13, from ip=12 -> 1
        assert_eq!(entry1_offset, 0); // zebra body at 12, from ip=12 -> 0
    }

    #[test]
    fn execute_from_bytes_truncated() {
        let err = ExecuteProgram::from_bytes(&[0x00, 0x01]).unwrap_err();
        assert!(matches!(err, VMError::DecodeError{ref reason} if reason == "truncated"));
    }

    #[test]
    fn execute_from_bytes_bad_magic() {
        let err = ExecuteProgram::from_bytes(b"BADMA\x00\x02\x00").unwrap_err();
        assert!(matches!(err, VMError::DecodeError{ref reason} if reason == "bad magic"));
    }

    #[test]
    fn execute_from_bytes_bad_prefix() {
        let mut bytes = Vec::new();
        MAGIC.encode(&mut bytes);
        CURRENT_VERSION.encode(&mut bytes);
        b"WRONG_PREFIX".to_vec().encode(&mut bytes);
        let err = ExecuteProgram::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, VMError::DecodeError{ref reason} if reason == "bad prefix"));
    }

    #[test]
    fn execute_from_bytes_unsupported_version() {
        let mut bytes = Vec::new();
        MAGIC.encode(&mut bytes);
        Version::new(255, 0, 0).encode(&mut bytes);
        let err = ExecuteProgram::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, VMError::DecodeError{ref reason} if reason == "unsupported version"));
    }

    #[test]
    fn execute_from_bytes_trailing_bytes() {
        let program = ExecuteProgram::new(Hash::zero(), 0, vec![], vec![]);
        let mut bytes = program.to_bytes().to_vec();
        bytes.push(0xFF);
        let err = ExecuteProgram::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, VMError::DecodeError{ref reason} if reason == "trailing bytes"));
    }
}
