use solana_sdk::{pubkey::Pubkey, signature::Signature};

/* 10MB */
pub const REDACTED_GEYSER_PACKET_MAX_SIZE: u32 = 10 * 1024 * 1024;

/* 20GB, assuming we don't take more than a second to send the entire pool on a 10G NIC, although the receiver's end will sometimes make back pressure. */
pub const REDACTED_GEYSER_MEMORY_POOL_SIZE: usize = 20 * 1024 * 1024 * 1024;

/* 1GB allocated on each socket on the server for backpressure (this is in case the receiver is slow, we will end up overwriting packets by the time he acknowledges.) */
pub const REDACTED_GEYSER_SERVER_BACKPRESSURE: usize = 1 * 1024 * 1024 * 1024;

/* 1 million pointers (work orders) of packets to be sent */
pub const REDACTED_GEYSER_SERVER_WORK_ORDERS: usize = 1_000_000;

/* The maximum amount of clients we've currently set to handle, this can be increased/decreased at will.
 * Ideally it's not too high as we have to iterate over the clients when we're sending packets.
 */
pub const REDACTED_GEYSER_MAX_CLIENTS: usize = 8;

/* Operation types seen in the transfer to designate the serialization/deserialization type */
pub const REDACTED_GEYSER_SET_PROGRAM_CONFIG: u8 = 0;
pub const REDACTED_GEYSER_NOTIFY_ACCOUNT_UPDATE: u8 = 1;

/* Guard bytes used to verify our serialization when sending and also when receiving packets. */
pub const REDACTED_GEYSER_MAGIC_GUARD_START: u8 = 0x9A;
pub const REDACTED_GEYSER_MAGIC_GUARD_END: u8 = 0xA9;

/* The header size of the packets */
pub const REDACTED_GEYSER_PACKET_HEADER_SIZE: usize = 6;

pub enum RedactedGeyserError {
    InvalidRequest,
    AbruptDisconnect,
}

#[derive(Clone)]
pub struct RedactedGeyserRequestProgramConfig {
    pub program_list: Vec<Pubkey>,
}

pub struct RedactedGeyserAccountUpdate {
    pub pubkey: Pubkey,
    pub signature: Option<Signature>,
    pub slot: u64,
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: Pubkey,
    pub executable: bool,
    pub rent_epoch: u64,
    pub write_version: u64,
    pub is_sandwich: bool,
}
