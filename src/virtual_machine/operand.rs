use crate::virtual_machine::errors::VMError;

/// Minimum byte length for compact i64 encoding.
pub const COMPACT_I64_MIN_BYTES: u8 = 1;
/// Maximum byte length for compact i64 encoding.
pub const COMPACT_I64_MAX_BYTES: u8 = 8;
/// Dynamic metadata carries at most three slots.
pub const METADATA_DYNAMIC_SLOT_COUNT: usize = 3;
/// Radix used by Src metadata states.
pub const SRC_METADATA_RADIX: u8 = 8;
/// Radix used by Addr metadata states.
pub const ADDR_METADATA_RADIX: u8 = 4;
/// Radix used by ImmI32 metadata states (power of 2 for shift-based decoding).
pub const IMM_I32_METADATA_RADIX: u8 = 4;

/// Shorthand for constructing a [`VMError::DecodeError`] from a string-like reason.
fn decode_error(reason: impl Into<String>) -> VMError {
    VMError::DecodeError {
        reason: reason.into(),
    }
}

/// Returns a [`VMError::DecodeError`] indicating that the dynamic slot count
/// exceeded [`METADATA_DYNAMIC_SLOT_COUNT`].
pub(crate) fn metadata_slot_overflow_error() -> VMError {
    decode_error(format!(
        "metadata supports at most {METADATA_DYNAMIC_SLOT_COUNT} dynamic operands"
    ))
}

/// Src metadata state used by mixed-radix metadata encoding.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrcMetadataState {
    Reg = 0,
    RefLen1 = 1,
    RefLen2 = 2,
    RefLen4 = 3,
    I64Len1 = 4,
    I64Len2 = 5,
    I64Len4 = 6,
    I64Len8 = 7,
}

impl SrcMetadataState {
    /// Returns the number of payload bytes this state requires after the metadata byte.
    pub const fn payload_len(self) -> usize {
        match self {
            Self::Reg => 1,
            Self::RefLen1 => 1,
            Self::RefLen2 => 2,
            Self::RefLen4 => 4,
            Self::I64Len1 => 1,
            Self::I64Len2 => 2,
            Self::I64Len4 => 4,
            Self::I64Len8 => 8,
        }
    }

    /// Returns the compact i64 byte length if this state is an i64 variant, or `None`.
    pub const fn i64_len(self) -> Option<u8> {
        match self {
            Self::I64Len1 => Some(1),
            Self::I64Len2 => Some(2),
            Self::I64Len4 => Some(4),
            Self::I64Len8 => Some(8),
            _ => None,
        }
    }

    /// Returns the compact reference byte length if this state is a Ref variant, or `None`.
    pub const fn ref_len(self) -> Option<u8> {
        match self {
            Self::RefLen1 => Some(1),
            Self::RefLen2 => Some(2),
            Self::RefLen4 => Some(4),
            _ => None,
        }
    }

    /// Converts a 2-bit length code (`00`/`01`/`10`/`11`) to the corresponding i64 state.
    pub const fn from_i64_len_code(code: u8) -> Self {
        match metadata_len_from_code(code) {
            1 => Self::I64Len1,
            2 => Self::I64Len2,
            4 => Self::I64Len4,
            _ => Self::I64Len8,
        }
    }
}

impl TryFrom<u8> for SrcMetadataState {
    type Error = VMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Reg),
            1 => Ok(Self::RefLen1),
            2 => Ok(Self::RefLen2),
            3 => Ok(Self::RefLen4),
            4 => Ok(Self::I64Len1),
            5 => Ok(Self::I64Len2),
            6 => Ok(Self::I64Len4),
            7 => Ok(Self::I64Len8),
            _ => Err(decode_error(format!("invalid Src metadata state {value}"))),
        }
    }
}

/// Addr metadata state used by mixed-radix metadata encoding.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrMetadataState {
    Reg = 0,
    U32Len1 = 1,
    U32Len2 = 2,
    U32Len4 = 3,
}

impl AddrMetadataState {
    /// Returns the number of payload bytes this state requires after the metadata byte.
    pub const fn payload_len(self) -> usize {
        match self {
            Self::Reg => 1,
            Self::U32Len1 => 1,
            Self::U32Len2 => 2,
            Self::U32Len4 => 4,
        }
    }

    /// Returns the compact u32 byte length if this state is a u32 variant, or `None`.
    pub const fn u32_len(self) -> Option<u8> {
        match self {
            Self::U32Len1 => Some(1),
            Self::U32Len2 => Some(2),
            Self::U32Len4 => Some(4),
            _ => None,
        }
    }
}

impl TryFrom<u8> for AddrMetadataState {
    type Error = VMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Reg),
            1 => Ok(Self::U32Len1),
            2 => Ok(Self::U32Len2),
            3 => Ok(Self::U32Len4),
            _ => Err(decode_error(format!("invalid Addr metadata state {value}"))),
        }
    }
}

/// ImmI32 metadata state used by mixed-radix metadata encoding.
///
/// State 3 (`Reserved`) is never emitted but exists so that the radix is 4
/// (a power of two), allowing the compiler to replace `%` / `/` with
/// bitwise `&` / `>>` during metadata decoding.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImmI32MetadataState {
    Len1 = 0,
    Len2 = 1,
    Len4 = 2,
    /// Padding state to make the radix a power of two. Never emitted.
    Reserved = 3,
}

impl ImmI32MetadataState {
    /// Returns the number of payload bytes this state requires after the metadata byte.
    pub const fn payload_len(self) -> usize {
        match self {
            Self::Len1 => 1,
            Self::Len2 => 2,
            Self::Len4 | Self::Reserved => 4,
        }
    }

    /// Returns the most compact state that can represent the given i32 value.
    pub fn from_value(value: i32) -> Self {
        if is_i64_representable_in_len(value as i64, 1) {
            Self::Len1
        } else if is_i64_representable_in_len(value as i64, 2) {
            Self::Len2
        } else {
            Self::Len4
        }
    }
}

impl TryFrom<u8> for ImmI32MetadataState {
    type Error = VMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Len1),
            1 => Ok(Self::Len2),
            2 => Ok(Self::Len4),
            3 => Ok(Self::Reserved),
            _ => Err(decode_error(format!(
                "invalid ImmI32 metadata state {value}"
            ))),
        }
    }
}

/// Kind discriminator for a dynamic metadata slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataSlotKind {
    /// Dynamic source operand (register, immediate, or reference).
    Src,
    /// Dynamic address operand (register or immediate u32).
    Addr,
    /// Compact i32 immediate operand.
    ImmI32,
}

/// Encoded metadata slot state and its radix domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataSlotEncoding {
    /// The operand kind this slot encodes.
    pub kind: MetadataSlotKind,
    /// Raw state value within the kind's radix domain.
    pub state: u8,
}

impl MetadataSlotEncoding {
    /// Creates a Src metadata slot from the given state.
    pub const fn src(state: SrcMetadataState) -> Self {
        Self {
            kind: MetadataSlotKind::Src,
            state: state as u8,
        }
    }

    /// Creates an Addr metadata slot from the given state.
    pub const fn addr(state: AddrMetadataState) -> Self {
        Self {
            kind: MetadataSlotKind::Addr,
            state: state as u8,
        }
    }

    /// Creates an ImmI32 metadata slot from the given state.
    pub const fn imm_i32(state: ImmI32MetadataState) -> Self {
        Self {
            kind: MetadataSlotKind::ImmI32,
            state: state as u8,
        }
    }

    /// Returns the mixed-radix base for this slot's kind.
    pub const fn radix(self) -> u8 {
        match self.kind {
            MetadataSlotKind::Src => SRC_METADATA_RADIX,
            MetadataSlotKind::Addr => ADDR_METADATA_RADIX,
            MetadataSlotKind::ImmI32 => IMM_I32_METADATA_RADIX,
        }
    }
}

/// Returns `true` when `value` can be sign-extended back to i64 from `len` LE bytes.
fn is_i64_representable_in_len(value: i64, len: usize) -> bool {
    let mut extended = [0u8; 8];
    let bytes = value.to_le_bytes();
    extended[..len].copy_from_slice(&bytes[..len]);
    if len < 8 && (extended[len - 1] & 0x80) != 0 {
        extended[len..].fill(0xFF);
    }
    i64::from_le_bytes(extended) == value
}

/// Returns the minimal compact byte length (1..=8) that can represent `value`.
pub(crate) fn compact_i64_len(value: i64) -> u8 {
    for len in COMPACT_I64_MIN_BYTES..=COMPACT_I64_MAX_BYTES {
        if is_i64_representable_in_len(value, len as usize) {
            return len;
        }
    }
    COMPACT_I64_MAX_BYTES
}

/// Encodes `value` using an explicit compact byte length (`1..=8`).
///
/// Returns an error if `len` is invalid or if `value` cannot be represented in
/// exactly `len` bytes with sign extension.
pub(crate) fn encode_i64_compact(value: i64, len: u8) -> Result<Vec<u8>, VMError> {
    if !(COMPACT_I64_MIN_BYTES..=COMPACT_I64_MAX_BYTES).contains(&len) {
        return Err(decode_error(format!(
            "invalid compact i64 length {len}, expected 1..=8"
        )));
    }
    let len = len as usize;
    if !is_i64_representable_in_len(value, len) {
        return Err(decode_error(format!(
            "value {value} cannot be represented in {len} bytes"
        )));
    }
    Ok(value.to_le_bytes()[..len].to_vec())
}

/// Decodes a compact i64 payload using an explicit byte length (`1..=8`).
///
/// The input slice may contain trailing bytes; only the first `len` bytes are
/// consumed.
pub(crate) fn decode_i64_compact(bytes: &[u8], len: u8) -> Result<i64, VMError> {
    if !(COMPACT_I64_MIN_BYTES..=COMPACT_I64_MAX_BYTES).contains(&len) {
        return Err(decode_error(format!(
            "invalid compact i64 length {len}, expected 1..=8"
        )));
    }
    let len = len as usize;
    if bytes.len() < len {
        return Err(decode_error(format!(
            "compact i64 decode needs {len} bytes, got {}",
            bytes.len()
        )));
    }

    let mut out = [0u8; 8];
    out[..len].copy_from_slice(&bytes[..len]);

    // Sign-extend when the compact payload has its sign bit set.
    if len < 8 && (out[len - 1] & 0x80) != 0 {
        out[len..].fill(0xFF);
    }

    Ok(i64::from_le_bytes(out))
}

/// Encodes `value` using a compact i32 byte length (`1`, `2`, or `4`).
pub(crate) fn encode_i32_compact(value: i32, len: u8) -> Result<Vec<u8>, VMError> {
    if !matches!(len, 1 | 2 | 4) {
        return Err(decode_error(format!(
            "invalid compact i32 length {len}, expected 1/2/4"
        )));
    }
    let len_usize = len as usize;
    if !is_i64_representable_in_len(value as i64, len_usize) {
        return Err(decode_error(format!(
            "value {value} cannot be represented in {len} bytes"
        )));
    }
    Ok(value.to_le_bytes()[..len_usize].to_vec())
}

/// Decodes a compact i32 payload using byte length (`1`, `2`, or `4`).
pub(crate) fn decode_i32_compact(bytes: &[u8], len: u8) -> Result<i32, VMError> {
    if !matches!(len, 1 | 2 | 4) {
        return Err(decode_error(format!(
            "invalid compact i32 length {len}, expected 1/2/4"
        )));
    }
    let value = decode_i64_compact(bytes, len)?;
    i32::try_from(value).map_err(|_| decode_error(format!("decoded i32 out of range: {value}")))
}

/// Encodes `value` using a compact u32 byte length (`1`, `2`, or `4`).
pub(crate) fn encode_u32_compact(value: u32, len: u8) -> Result<Vec<u8>, VMError> {
    if !matches!(len, 1 | 2 | 4) {
        return Err(decode_error(format!(
            "invalid compact u32 length {len}, expected 1/2/4"
        )));
    }
    if (len == 1 && value > u8::MAX as u32) || (len == 2 && value > u16::MAX as u32) {
        return Err(decode_error(format!(
            "value {value} cannot be represented in {len} bytes"
        )));
    }
    Ok(value.to_le_bytes()[..len as usize].to_vec())
}

/// Decodes a compact u32 payload using byte length (`1`, `2`, or `4`).
pub(crate) fn decode_u32_compact(bytes: &[u8], len: u8) -> Result<u32, VMError> {
    if !matches!(len, 1 | 2 | 4) {
        return Err(decode_error(format!(
            "invalid compact u32 length {len}, expected 1/2/4"
        )));
    }
    let len = len as usize;
    if bytes.len() < len {
        return Err(decode_error(format!(
            "compact u32 decode needs {len} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 4];
    out[..len].copy_from_slice(&bytes[..len]);
    Ok(u32::from_le_bytes(out))
}

/// Decodes a compact i64 payload without bounds or length validation.
/// # Safety
/// `bytes` must contain at least `len` readable bytes. `len` must be `1`, `2`,
/// `4`, or `8`.
#[inline(always)]
pub(crate) unsafe fn decode_i64_compact_unchecked(bytes: &[u8], len: u8) -> i64 {
    unsafe {
        let p = bytes.as_ptr();
        match len {
            1 => *p as i8 as i64,
            2 => i16::from_le_bytes(*(p as *const [u8; 2])) as i64,
            4 => i32::from_le_bytes(*(p as *const [u8; 4])) as i64,
            _ => i64::from_le_bytes(*(p as *const [u8; 8])),
        }
    }
}

/// Decodes a compact i32 payload without bounds or length validation.
/// # Safety
/// `bytes` must contain at least `len` readable bytes. `len` must be `1`, `2`,
/// or `4`.
#[inline(always)]
pub(crate) unsafe fn decode_i32_compact_unchecked(bytes: &[u8], len: u8) -> i32 {
    unsafe {
        let p = bytes.as_ptr();
        match len {
            1 => *p as i8 as i32,
            2 => i16::from_le_bytes(*(p as *const [u8; 2])) as i32,
            _ => i32::from_le_bytes(*(p as *const [u8; 4])),
        }
    }
}

/// Decodes a compact u32 payload without bounds or length validation.
/// # Safety
/// `bytes` must contain at least `len` readable bytes. `len` must be `1`, `2`,
/// or `4`.
#[inline(always)]
pub(crate) unsafe fn decode_u32_compact_unchecked(bytes: &[u8], len: u8) -> u32 {
    unsafe {
        let p = bytes.as_ptr();
        match len {
            1 => *p as u32,
            2 => u16::from_le_bytes(*(p as *const [u8; 2])) as u32,
            _ => u32::from_le_bytes(*(p as *const [u8; 4])),
        }
    }
}

/// Returns `(byte_len, len_code)` for compact i64 metadata encoding.
pub(crate) fn metadata_i64_len_and_code(value: i64) -> (u8, u8) {
    let min_len = compact_i64_len(value);
    if min_len <= 1 {
        (1, 0b00)
    } else if min_len <= 2 {
        (2, 0b01)
    } else if min_len <= 4 {
        (4, 0b10)
    } else {
        (8, 0b11)
    }
}

/// Decodes compact i64 length code `00/01/10/11` to `1/2/4/8` bytes.
pub(crate) const fn metadata_len_from_code(code: u8) -> u8 {
    match code & 0b11 {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        _ => 8,
    }
}

/// Returns true when metadata indicates compact concat form (A bit).
pub(crate) fn metadata_concat_flag(metadata: u8) -> bool {
    (metadata & 0b1000_0000) != 0
}

/// Returns the mixed-radix payload value used to decode dynamic metadata slots.
///
/// For concat-capable `(Reg, Src, Src)` instructions, bit 7 is reserved for the
/// concat flag and excluded from the payload value.
pub(crate) fn metadata_payload_value(metadata: u8, concat_capable_pair: bool) -> u16 {
    if concat_capable_pair {
        (metadata & 0b0111_1111) as u16
    } else {
        metadata as u16
    }
}

/// Consumes and returns the next Src metadata state from a mixed-radix cursor.
pub(crate) fn metadata_consume_src_state(cursor: &mut u16) -> Result<SrcMetadataState, VMError> {
    let raw = (*cursor % SRC_METADATA_RADIX as u16) as u8;
    *cursor /= SRC_METADATA_RADIX as u16;
    SrcMetadataState::try_from(raw)
}

/// Consumes and returns the next Src metadata state from a mixed-radix cursor.
/// # Safety
/// The caller must guarantee that the cursor was produced by valid metadata
/// encoding. The raw value `cursor % 8` is transmuted directly to
/// [`SrcMetadataState`], which is `#[repr(u8)]` with discriminants `0..8`.
#[inline(always)]
pub(crate) unsafe fn metadata_consume_src_state_unchecked(cursor: &mut u16) -> SrcMetadataState {
    let raw = (*cursor & 7) as u8;
    *cursor >>= 3;
    unsafe { std::mem::transmute(raw) }
}

/// Consumes and returns the next Addr metadata state from a mixed-radix cursor.
pub(crate) fn metadata_consume_addr_state(cursor: &mut u16) -> Result<AddrMetadataState, VMError> {
    let raw = (*cursor % ADDR_METADATA_RADIX as u16) as u8;
    *cursor /= ADDR_METADATA_RADIX as u16;
    AddrMetadataState::try_from(raw)
}

/// Consumes and returns the next Addr metadata state from a mixed-radix cursor.
/// # Safety
/// The caller must guarantee that the cursor was produced by valid metadata
/// encoding. The raw value `cursor % 4` is transmuted directly to
/// [`AddrMetadataState`], which is `#[repr(u8)]` with discriminants `0..4`.
#[inline(always)]
pub(crate) unsafe fn metadata_consume_addr_state_unchecked(cursor: &mut u16) -> AddrMetadataState {
    let raw = (*cursor & 3) as u8;
    *cursor >>= 2;
    unsafe { std::mem::transmute(raw) }
}

/// Consumes and returns the next ImmI32 metadata state from a mixed-radix cursor.
pub(crate) fn metadata_consume_imm_i32_state(
    cursor: &mut u16,
) -> Result<ImmI32MetadataState, VMError> {
    let raw = (*cursor % IMM_I32_METADATA_RADIX as u16) as u8;
    *cursor /= IMM_I32_METADATA_RADIX as u16;
    ImmI32MetadataState::try_from(raw)
}

/// Consumes and returns the next ImmI32 metadata state from a mixed-radix cursor.
/// # Safety
/// The caller must guarantee that the cursor was produced by valid metadata
/// encoding. The raw value `cursor % 4` is transmuted directly to
/// [`ImmI32MetadataState`], which is `#[repr(u8)]` with discriminants `0..4`.
#[inline(always)]
pub(crate) unsafe fn metadata_consume_imm_i32_state_unchecked(
    cursor: &mut u16,
) -> ImmI32MetadataState {
    let raw = (*cursor & 3) as u8;
    *cursor >>= 2;
    unsafe { std::mem::transmute(raw) }
}

/// Encodes one metadata byte from up to three dynamic Src/Addr slots.
pub(crate) fn encode_metadata_byte(
    concat: bool,
    dynamic_slots: &[MetadataSlotEncoding],
) -> Result<u8, VMError> {
    if dynamic_slots.len() > METADATA_DYNAMIC_SLOT_COUNT {
        return Err(metadata_slot_overflow_error());
    }

    if dynamic_slots.is_empty() {
        return Ok(0);
    }

    let mut value = 0u16;
    let mut factor = 1u16;
    for slot in dynamic_slots {
        let radix = slot.radix() as u16;
        if slot.state as u16 >= radix {
            return Err(decode_error(format!(
                "metadata state {} out of range for radix {radix}",
                slot.state
            )));
        }
        value = value
            .checked_add((slot.state as u16).saturating_mul(factor))
            .ok_or_else(|| decode_error("metadata value overflow"))?;
        factor = factor
            .checked_mul(radix)
            .ok_or_else(|| decode_error("metadata radix product overflow"))?;
    }

    if concat {
        let concat_layout = dynamic_slots.len() == 2
            && dynamic_slots
                .iter()
                .all(|s| s.kind == MetadataSlotKind::Src);
        if !concat_layout {
            return Err(decode_error(
                "concat flag is only supported for 2-Src metadata layouts",
            ));
        }
        if value > 0x7F {
            return Err(decode_error("concat metadata payload exceeds 7 bits"));
        }
        return Ok(0b1000_0000 | value as u8);
    }

    if value > 0xFF {
        return Err(decode_error("metadata payload exceeds 8 bits"));
    }

    Ok(value as u8)
}

/// Source operand for instructions that accept registers, immediates, or references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SrcOperand {
    /// Register index.
    Reg(u8),
    /// Immediate boolean value.
    Bool(bool),
    /// Immediate 64-bit signed integer.
    I64(i64),
    /// Reference index into the string pool / heap.
    Ref(u32),
}

impl SrcOperand {
    /// Returns the legacy encoded byte size of this operand (tag byte + payload).
    pub const fn size(&self) -> usize {
        1 + match self {
            SrcOperand::Reg(_) => 1,
            SrcOperand::Bool(_) => 1,
            SrcOperand::I64(_) => 8,
            SrcOperand::Ref(_) => 4,
        }
    }

    /// Returns a human-readable type name for error messages.
    pub const fn to_string(&self) -> &'static str {
        match self {
            SrcOperand::Reg(_) => "Register",
            SrcOperand::Bool(_) => "Boolean",
            SrcOperand::I64(_) => "Integer",
            SrcOperand::Ref(_) => "Reference",
        }
    }
}

/// Address operand for memory operations.
///
/// Can be either an immediate 32-bit address or a register containing the address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddrOperand {
    /// Immediate 32-bit address value.
    U32(u32),
    /// Register index containing the address.
    Reg(u8),
}

impl AddrOperand {
    /// Returns the encoded byte size of this operand (tag byte + payload).
    pub const fn size(&self) -> usize {
        1 + match self {
            AddrOperand::Reg(_) => 1,
            AddrOperand::U32(_) => 4,
        }
    }

    /// Returns a human-readable type name for error messages.
    pub const fn to_string(&self) -> &'static str {
        match self {
            AddrOperand::Reg(_) => "Register",
            AddrOperand::U32(_) => "Integer",
        }
    }
}

/// Src type code used by metadata-based operand encoding.
#[cfg(test)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrcTypeCode {
    Reg = 0b00,
    Bool = 0b01,
    I64 = 0b10,
    Ref = 0b11,
}

#[cfg(test)]
impl SrcTypeCode {
    /// Returns the type code corresponding to the given operand variant.
    pub const fn from_operand(value: &SrcOperand) -> Self {
        match value {
            SrcOperand::Reg(_) => Self::Reg,
            SrcOperand::Bool(_) => Self::Bool,
            SrcOperand::I64(_) => Self::I64,
            SrcOperand::Ref(_) => Self::Ref,
        }
    }
}

#[cfg(test)]
impl TryFrom<u8> for SrcTypeCode {
    type Error = VMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(Self::Reg),
            0b01 => Ok(Self::Bool),
            0b10 => Ok(Self::I64),
            0b11 => Ok(Self::Ref),
            _ => Err(VMError::InvalidOperandTag {
                tag: value,
                offset: 0,
            }),
        }
    }
}

/// Addr type code used by metadata-based operand encoding.
#[cfg(test)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrTypeCode {
    Reg = 0b00,
    U32 = 0b01,
}

#[cfg(test)]
impl AddrTypeCode {
    /// Returns the type code corresponding to the given operand variant.
    pub const fn from_operand(value: &AddrOperand) -> Self {
        match value {
            AddrOperand::Reg(_) => Self::Reg,
            AddrOperand::U32(_) => Self::U32,
        }
    }
}

#[cfg(test)]
impl TryFrom<u8> for AddrTypeCode {
    type Error = VMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b00 => Ok(Self::Reg),
            0b01 => Ok(Self::U32),
            _ => Err(VMError::InvalidOperandTag {
                tag: value,
                offset: 0,
            }),
        }
    }
}

/// Encodes non-i64 Src variants to `(type_code, payload)` for metadata encoding.
///
/// Returns `None` for `SrcOperand::I64`, which is encoded through compact i64 helpers.
#[cfg(test)]
pub(crate) fn encode_src_non_i64(operand: &SrcOperand) -> Option<(SrcTypeCode, Vec<u8>)> {
    match operand {
        SrcOperand::Reg(r) => Some((SrcTypeCode::Reg, vec![*r])),
        SrcOperand::Bool(b) => Some((SrcTypeCode::Bool, vec![if *b { 1 } else { 0 }])),
        SrcOperand::Ref(r) => Some((SrcTypeCode::Ref, r.to_le_bytes().to_vec())),
        SrcOperand::I64(_) => None,
    }
}

/// Decodes non-i64 Src variants from a `(type_code, payload)` pair.
///
/// Returns `(operand, bytes_consumed)`.
#[cfg(test)]
pub(crate) fn decode_src_non_i64(
    code: SrcTypeCode,
    payload: &[u8],
) -> Result<(SrcOperand, usize), VMError> {
    match code {
        SrcTypeCode::Reg => {
            let v = payload
                .first()
                .copied()
                .ok_or_else(|| decode_error("src reg payload requires 1 byte"))?;
            Ok((SrcOperand::Reg(v), 1))
        }
        SrcTypeCode::Bool => {
            let v = payload
                .first()
                .copied()
                .ok_or_else(|| decode_error("src bool payload requires 1 byte"))?;
            Ok((SrcOperand::Bool(v != 0), 1))
        }
        SrcTypeCode::Ref => {
            if payload.len() < 4 {
                return Err(decode_error("src ref payload requires 4 bytes"));
            }
            let raw: [u8; 4] = payload[..4].try_into().unwrap();
            Ok((SrcOperand::Ref(u32::from_le_bytes(raw)), 4))
        }
        SrcTypeCode::I64 => Err(decode_error(
            "SrcTypeCode::I64 must be decoded via compact i64 helpers",
        )),
    }
}

/// Encodes Addr variants to `(type_code, payload)` for metadata encoding.
#[cfg(test)]
pub(crate) fn encode_addr(operand: &AddrOperand) -> (AddrTypeCode, Vec<u8>) {
    match operand {
        AddrOperand::Reg(r) => (AddrTypeCode::Reg, vec![*r]),
        AddrOperand::U32(v) => (AddrTypeCode::U32, v.to_le_bytes().to_vec()),
    }
}

/// Decodes Addr variants from a `(type_code, payload)` pair.
///
/// Returns `(operand, bytes_consumed)`.
#[cfg(test)]
pub(crate) fn decode_addr(
    code: AddrTypeCode,
    payload: &[u8],
) -> Result<(AddrOperand, usize), VMError> {
    match code {
        AddrTypeCode::Reg => {
            let v = payload
                .first()
                .copied()
                .ok_or_else(|| decode_error("addr reg payload requires 1 byte"))?;
            Ok((AddrOperand::Reg(v), 1))
        }
        AddrTypeCode::U32 => {
            if payload.len() < 4 {
                return Err(decode_error("addr u32 payload requires 4 bytes"));
            }
            let raw: [u8; 4] = payload[..4].try_into().unwrap();
            Ok((AddrOperand::U32(u32::from_le_bytes(raw)), 4))
        }
    }
}

/// Legacy per-operand type tag byte used before metadata-based encoding.
#[repr(u8)]
#[derive(Debug)]
pub enum OperandTag {
    /// Register operand (1-byte payload: register index).
    Register = 0,
    /// Boolean operand (1-byte payload: 0 or 1).
    Boolean = 1,
    /// 64-bit integer operand (8-byte little-endian payload).
    I64 = 2,
    /// Reference operand (4-byte little-endian payload: heap index).
    Ref = 3,
}

impl TryFrom<u8> for OperandTag {
    type Error = VMError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Register),
            1 => Ok(Self::Boolean),
            2 => Ok(Self::I64),
            3 => Ok(Self::Ref),
            _ => Err(VMError::InvalidOperandTag {
                tag: value,
                offset: 0,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn src_operand_size_reg() {
        assert_eq!(SrcOperand::Reg(0).size(), 2);
        assert_eq!(SrcOperand::Reg(255).size(), 2);
    }

    #[test]
    fn src_operand_size_bool() {
        assert_eq!(SrcOperand::Bool(true).size(), 2);
        assert_eq!(SrcOperand::Bool(false).size(), 2);
    }

    #[test]
    fn src_operand_size_i64() {
        assert_eq!(SrcOperand::I64(0).size(), 9);
        assert_eq!(SrcOperand::I64(i64::MAX).size(), 9);
        assert_eq!(SrcOperand::I64(i64::MIN).size(), 9);
    }

    #[test]
    fn src_operand_size_ref() {
        assert_eq!(SrcOperand::Ref(0).size(), 5);
        assert_eq!(SrcOperand::Ref(u32::MAX).size(), 5);
    }

    #[test]
    fn src_operand_to_string() {
        assert_eq!(SrcOperand::Reg(0).to_string(), "Register");
        assert_eq!(SrcOperand::Bool(true).to_string(), "Boolean");
        assert_eq!(SrcOperand::I64(42).to_string(), "Integer");
        assert_eq!(SrcOperand::Ref(100).to_string(), "Reference");
    }

    #[test]
    fn operand_tag_try_from_valid() {
        assert_eq!(OperandTag::try_from(0).unwrap() as u8, 0);
        assert_eq!(OperandTag::try_from(1).unwrap() as u8, 1);
        assert_eq!(OperandTag::try_from(2).unwrap() as u8, 2);
        assert_eq!(OperandTag::try_from(3).unwrap() as u8, 3);
    }

    #[test]
    fn operand_tag_try_from_invalid() {
        for tag in 4..=255u8 {
            let err = OperandTag::try_from(tag).unwrap_err();
            assert!(matches!(err, VMError::InvalidOperandTag { tag: t, .. } if t == tag));
        }
    }

    #[test]
    fn addr_operand_size() {
        assert_eq!(AddrOperand::Reg(0).size(), 2);
        assert_eq!(AddrOperand::Reg(255).size(), 2);
        assert_eq!(AddrOperand::U32(0).size(), 5);
        assert_eq!(AddrOperand::U32(u32::MAX).size(), 5);
    }

    #[test]
    fn addr_operand_to_string() {
        assert_eq!(AddrOperand::Reg(0).to_string(), "Register");
        assert_eq!(AddrOperand::U32(42).to_string(), "Integer");
    }

    #[test]
    fn compact_i64_len_boundaries() {
        assert_eq!(compact_i64_len(0), 1);
        assert_eq!(compact_i64_len(127), 1);
        assert_eq!(compact_i64_len(128), 2);
        assert_eq!(compact_i64_len(-128), 1);
        assert_eq!(compact_i64_len(-129), 2);
        assert_eq!(compact_i64_len(i64::MAX), 8);
        assert_eq!(compact_i64_len(i64::MIN), 8);
    }

    #[test]
    fn compact_i64_roundtrip_minimal_len() {
        let values = [
            -129i64,
            -128,
            -1,
            0,
            1,
            42,
            127,
            128,
            255,
            256,
            i64::MIN,
            i64::MAX,
        ];

        for value in values {
            let len = compact_i64_len(value);
            let encoded = encode_i64_compact(value, len).unwrap();
            let decoded = decode_i64_compact(&encoded, len).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn compact_i64_rejects_invalid_len_and_truncation() {
        assert!(encode_i64_compact(1, 0).is_err());
        assert!(encode_i64_compact(1, 9).is_err());
        assert!(encode_i64_compact(128, 1).is_err());
        assert!(decode_i64_compact(&[0x7F], 0).is_err());
        assert!(decode_i64_compact(&[0x7F], 2).is_err());
    }

    #[test]
    fn compact_u32_roundtrip_and_bounds() {
        let values = [0u32, 1, 42, 255, 256, 65_535, 65_536, u32::MAX];
        for value in values {
            let len = if value <= u8::MAX as u32 {
                1
            } else if value <= u16::MAX as u32 {
                2
            } else {
                4
            };
            let encoded = encode_u32_compact(value, len).unwrap();
            let decoded = decode_u32_compact(&encoded, len).unwrap();
            assert_eq!(decoded, value);
        }
        assert!(encode_u32_compact(256, 1).is_err());
        assert!(encode_u32_compact(65_536, 2).is_err());
        assert!(decode_u32_compact(&[0x01], 2).is_err());
    }

    #[test]
    fn src_type_code_mapping() {
        assert_eq!(
            SrcTypeCode::from_operand(&SrcOperand::Reg(1)),
            SrcTypeCode::Reg
        );
        assert_eq!(
            SrcTypeCode::from_operand(&SrcOperand::Bool(true)),
            SrcTypeCode::Bool
        );
        assert_eq!(
            SrcTypeCode::from_operand(&SrcOperand::I64(7)),
            SrcTypeCode::I64
        );
        assert_eq!(
            SrcTypeCode::from_operand(&SrcOperand::Ref(2)),
            SrcTypeCode::Ref
        );
        assert_eq!(SrcTypeCode::try_from(0b00).unwrap(), SrcTypeCode::Reg);
        assert_eq!(SrcTypeCode::try_from(0b01).unwrap(), SrcTypeCode::Bool);
        assert_eq!(SrcTypeCode::try_from(0b10).unwrap(), SrcTypeCode::I64);
        assert_eq!(SrcTypeCode::try_from(0b11).unwrap(), SrcTypeCode::Ref);
    }

    #[test]
    fn addr_type_code_mapping() {
        assert_eq!(
            AddrTypeCode::from_operand(&AddrOperand::Reg(1)),
            AddrTypeCode::Reg
        );
        assert_eq!(
            AddrTypeCode::from_operand(&AddrOperand::U32(7)),
            AddrTypeCode::U32
        );
        assert_eq!(AddrTypeCode::try_from(0b00).unwrap(), AddrTypeCode::Reg);
        assert_eq!(AddrTypeCode::try_from(0b01).unwrap(), AddrTypeCode::U32);
        assert!(AddrTypeCode::try_from(0b10).is_err());
    }

    #[test]
    fn encode_decode_non_i64_src_and_addr() {
        let (code, payload) = encode_src_non_i64(&SrcOperand::Reg(9)).unwrap();
        let (decoded, used) = decode_src_non_i64(code, &payload).unwrap();
        assert_eq!(decoded, SrcOperand::Reg(9));
        assert_eq!(used, 1);

        let (code, payload) = encode_src_non_i64(&SrcOperand::Bool(true)).unwrap();
        let (decoded, used) = decode_src_non_i64(code, &payload).unwrap();
        assert_eq!(decoded, SrcOperand::Bool(true));
        assert_eq!(used, 1);

        let (code, payload) = encode_src_non_i64(&SrcOperand::Ref(123)).unwrap();
        let (decoded, used) = decode_src_non_i64(code, &payload).unwrap();
        assert_eq!(decoded, SrcOperand::Ref(123));
        assert_eq!(used, 4);

        assert!(encode_src_non_i64(&SrcOperand::I64(1)).is_none());

        let (code, payload) = encode_addr(&AddrOperand::Reg(7));
        let (decoded, used) = decode_addr(code, &payload).unwrap();
        assert_eq!(decoded, AddrOperand::Reg(7));
        assert_eq!(used, 1);

        let (code, payload) = encode_addr(&AddrOperand::U32(0xDEAD_BEEF));
        let (decoded, used) = decode_addr(code, &payload).unwrap();
        assert_eq!(decoded, AddrOperand::U32(0xDEAD_BEEF));
        assert_eq!(used, 4);
    }
}
