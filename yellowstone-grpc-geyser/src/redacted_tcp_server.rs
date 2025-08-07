use crossbeam_channel::{Receiver, Sender};
use libc::{send, MSG_NOSIGNAL};
use solana_pubkey::Pubkey;
use std::collections::HashSet;
use std::io::{Error, Read};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::Builder;

use crate::redacted_memory_pool::{RedactedMemoryPool, set_thread_exclusivity};
use crate::redacted_tcp_types::{
    RedactedGeyserError, REDACTED_GEYSER_MAGIC_GUARD_END, REDACTED_GEYSER_MAGIC_GUARD_START, REDACTED_GEYSER_MAX_CLIENTS, REDACTED_GEYSER_MEMORY_POOL_SIZE, REDACTED_GEYSER_NOTIFY_ACCOUNT_UPDATE, REDACTED_GEYSER_PACKET_HEADER_SIZE, REDACTED_GEYSER_PACKET_MAX_SIZE, REDACTED_GEYSER_SERVER_BACKPRESSURE, REDACTED_GEYSER_SERVER_WORK_ORDERS, REDACTED_GEYSER_SET_PROGRAM_CONFIG
};

#[derive(Debug)]
pub struct RedactedGeyserServer {
    listener_host: String,

    listener_clients: [RawFd; REDACTED_GEYSER_MAX_CLIENTS], /* This is not a rolling window! */
    listener_client_count: AtomicUsize,

    listener_clients_channels: [(Sender<&'static mut [u8]>, Receiver<&'static mut [u8]>); REDACTED_GEYSER_MAX_CLIENTS],

    memory_pool: RedactedMemoryPool,
    geyser_program_list: RwLock<HashSet<Pubkey>>,
}

impl RedactedGeyserServer {
    pub fn new(address: &str) -> Arc<Self> {
        let memory_pool = RedactedMemoryPool::new(REDACTED_GEYSER_MEMORY_POOL_SIZE);
        let mut client_channels = Vec::with_capacity(REDACTED_GEYSER_MAX_CLIENTS);
        for _ in 0..REDACTED_GEYSER_MAX_CLIENTS {
            let (sender, receiver) = crossbeam_channel::bounded(REDACTED_GEYSER_SERVER_WORK_ORDERS);
            client_channels.push((sender, receiver));
        }

        Arc::new(Self {
            listener_host: address.to_string(),
            listener_clients: [0; REDACTED_GEYSER_MAX_CLIENTS],
            listener_client_count: AtomicUsize::new(0),

            listener_clients_channels: client_channels.try_into().unwrap(),

            memory_pool,
            geyser_program_list: RwLock::new(HashSet::new()),
        })
    }

    fn handle_set_program_config(self: &Arc<Self>, request_mem: &[u8]) {
        /* Reset current */
        self.geyser_program_list.write().unwrap().clear();

        /* Get the requested pubkeys */
        let mut offset = 0;
        while offset < request_mem.len() - 1 /* minus the magic guard */ {
            let mut program = [0; 32];
            program.copy_from_slice(&request_mem[offset..offset + 32]);
            self.geyser_program_list
                .write()
                .unwrap()
                .insert(Pubkey::new_from_array(program));
            offset += 32;
        }
    }

    fn handle_request(
        self: &Arc<Self>,
        _stream: &mut TcpStream,
        request_type: u8,
        request_mem: &[u8],
    ) -> Result<(), RedactedGeyserError> {
        /* We now have access to just the data we need, decode depending on the type. */
        match request_type {
            REDACTED_GEYSER_SET_PROGRAM_CONFIG => {
                self.handle_set_program_config(request_mem);
            }
            REDACTED_GEYSER_NOTIFY_ACCOUNT_UPDATE => {
                /* We don't need to do anything here, as the client will never send us this request. */
            }
            _ => {}
        }

        Ok(())
    }

    fn create_response(self: &Arc<Self>, request_type: u8, request_length: u32, request_mem: &mut [u8]) -> usize {
        request_mem[0] = REDACTED_GEYSER_MAGIC_GUARD_START;
        request_mem[1] = request_type as u8;
        request_mem[2..6].copy_from_slice(&(request_length - REDACTED_GEYSER_PACKET_HEADER_SIZE as u32).to_le_bytes());
        request_mem[request_mem.len() - 1] = REDACTED_GEYSER_MAGIC_GUARD_END;

        REDACTED_GEYSER_PACKET_HEADER_SIZE as usize
    }

    fn send_request(self: &Arc<Self>, data: &'static mut [u8]) -> Result<(), Error> {
            
        for i in 0..REDACTED_GEYSER_MAX_CLIENTS {
            let client = self.listener_clients[i];
            if client == 0 {
                continue;
            }

            unsafe {
                if self.listener_clients_channels[i].0.try_send(std::ptr::read(&data)).is_err() {
                    /* Client is falling behind, disconnect him, he sucks
                     * In all seriousness, this is bad for the validator/rpc itself, so we should disconnect him.
                     * The way to fix this is to process the packets faster on the client side, they merely have to be acknowledged by the kernel.
                     */
                    libc::close(client);
                    
                    let mut_self = &mut *((&**self) as *const RedactedGeyserServer as *mut RedactedGeyserServer);
                    mut_self.listener_clients[i] = 0;

                    continue;
                }
            }
        }

        Ok(())
    }

    fn thread_recv(self: &Arc<Self>, mut stream: TcpStream) {
        loop {
            /* Read 6 bytes
             * 1 byte for the magic guard start
             * 1 byte for the request type
             * 4 bytes for the request length
             */
            let mut buf: [u8; 6] = [0, 0, 0, 0, 0, 0];
            if let Err(_) = stream.read_exact(&mut buf) {
                break;
            }

            /* Verify the request type */
            let request_type = buf[1];
            match request_type {
                REDACTED_GEYSER_SET_PROGRAM_CONFIG => {}
                REDACTED_GEYSER_NOTIFY_ACCOUNT_UPDATE => {}
                _ => {
                    break;
                }
            };

            /* Verify the request length */
            let request_length = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
            if request_length > REDACTED_GEYSER_PACKET_MAX_SIZE {
                break;
            }

            /* Read the rest of the request */
            let request_mem = self.memory_pool.alloc(request_length as usize);
            if let Err(_) = stream.read_exact(request_mem) {
                break;
            }

            /* Handle the request */
            if let Err(_) = self.handle_request(&mut stream, request_type, request_mem) {
                break;
            }
        }
    }

    fn thread_send(self: &Arc<Self>, client_index: usize) {
        #[cfg(target_os = "linux")]
        set_thread_exclusivity();

        'outer: loop {
            let client = self.listener_clients[client_index];
            if client == 0 {
                break; /* The client was disconnected elsewhere */
            }

            let work_order = self.listener_clients_channels[client_index].1.recv();
            if work_order.is_err() {
                break; /* The client was disconnected elsewhere */
            }
            let work_order = work_order.unwrap();

            let mut remainder = work_order.len();
            loop {
                let sent = unsafe {
                    send(
                        client,
                        work_order.as_ptr() as *const c_void,
                        remainder,
                        MSG_NOSIGNAL,
                    )
                };

                if sent < 0 {
                    if Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK) {
                        std::thread::yield_now();
                        continue;
                    }

                    break 'outer; /* Disconnect the client */
                }
                
                remainder -= sent as usize;
                if remainder == 0 {
                    break;
                }
            }
        }
    }

    pub fn send_account_update(
        self: &Arc<Self>,
        pubkey: &[u8],
        signature: Option<&[u8; 64]>,
        slot: u64,
        is_sandwich: bool,
        lamports: u64,
        data: &[u8],
        owner: &Pubkey,
        executable: bool,
        rent_epoch: u64,
        write_version: u64,
        include_timestamp: bool,
    ) -> Result<(), Error> {
        if self.listener_client_count.load(Ordering::SeqCst) == 0 {
            return Ok(());
        }

        {
            let geyser_program_list = self.geyser_program_list.read().unwrap();
            if !geyser_program_list.is_empty() && !geyser_program_list.contains(owner) {
                return Ok(());
            }
        }
        // Calculate total size needed:
        // - 1 byte for the magic header start
        // - 1 byte for the request type
        // - 4 bytes for the length of the packet
        // - 32 bytes for pubkey
        // - 1 byte to indicate whether or not signature is present
        // - 64 bytes for signature
        // - 8 bytes for slot
        // - 8 bytes for lamports
        // - 8 bytes for data length
        // - N bytes for data
        // - 32 bytes for owner
        // - 1 byte for executable
        // - 8 bytes for rent_epoch
        // - 8 bytes for write_version
        // - 1 byte for is_sandwich
        // - 1 byte for include_timestamp
        // - 8 bytes for timestamp seconds
        // - 4 bytes for timestamp nanoseconds
        // - 1 byte for the magic header end
        let mut total_size = 1 + 1 + 4 + 32 + 1 + 8 + 8 + 8 + data.len() + 32 + 1 + 8 + 8 + 1 + 1;
        if signature.is_some() {
            total_size += 64;
        }

        if include_timestamp {
            total_size += 1 + 8 + 4;
        }

        let request_mem = self.memory_pool.alloc(total_size);
        let mut offset = self.create_response(REDACTED_GEYSER_NOTIFY_ACCOUNT_UPDATE, total_size as u32, request_mem);

        request_mem[offset..offset + 32].copy_from_slice(pubkey.as_ref());
        offset += 32;

        if let Some(signature) = signature {
            request_mem[offset] = 1; /* Set 1 to indicate present */
            offset += 1;
            request_mem[offset..offset + 64].copy_from_slice(signature.as_ref());
            offset += 64;
        } else {
            /* Set 0 to indicate not present */
            request_mem[offset] = 0;
            offset += 1;
        }

        request_mem[offset..offset + 8].copy_from_slice(&slot.to_le_bytes());
        offset += 8;

        request_mem[offset..offset + 8].copy_from_slice(&lamports.to_le_bytes());
        offset += 8;

        request_mem[offset..offset + 8].copy_from_slice(&(data.len() as u64).to_le_bytes());
        offset += 8;

        request_mem[offset..offset + data.len()].copy_from_slice(data);
        offset += data.len();

        request_mem[offset..offset + 32].copy_from_slice(owner.as_ref());
        offset += 32;

        request_mem[offset] = executable as u8;
        offset += 1;

        request_mem[offset..offset + 8].copy_from_slice(&rent_epoch.to_le_bytes());
        offset += 8;

        request_mem[offset..offset + 8].copy_from_slice(&write_version.to_le_bytes());
        offset += 8;

        request_mem[offset] = is_sandwich as u8;
        offset += 1;

        if include_timestamp {
            let timespec = unsafe {
                let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
                libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr());
                ts.assume_init()
            };

            request_mem[offset] = 1; /* Set 1 to indicate present */
            offset += 1;
            
            request_mem[offset..offset + 8].copy_from_slice(&timespec.tv_sec.to_le_bytes());
            offset += 8;
            
            let nanos = (timespec.tv_nsec % 1_000_000_000) as i32;
            request_mem[offset..offset + 4].copy_from_slice(&nanos.to_le_bytes());
        }
        else {
            /* Set 0 to indicate not present */
            request_mem[offset] = 0;
        }

        self.send_request(request_mem)?;

        Ok(())
    }

    pub fn start_server(self: &Arc<Self>) -> Result<(), Error> {
        let cloned_self = self.clone();
        Builder::new()
            .name("redacted_tcp_geyser_listener".to_string())
            .spawn(move || {

            let listener = TcpListener::bind(&cloned_self.listener_host);
            if listener.is_err() {
                panic!("Failed to bind to listener host: {}", cloned_self.listener_host);
            }
            let listener = listener.unwrap();
    
            /* Set nagle's algorithm */
            let fd = listener.as_raw_fd();
            let result = unsafe {
                let mut flag: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_NODELAY,
                    &mut flag as *mut _ as *const _,
                    std::mem::size_of_val(&flag) as u32,
                )
            };
            if result != 0 {
                panic!("Failed to set nagle's algorithm.");
            }

            #[cfg(target_os = "linux")]
            {
                let quickack: libc::c_int = 1;
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_QUICKACK,
                        &quickack as *const _ as *const _,
                        std::mem::size_of_val(&quickack) as libc::socklen_t,
                    )
                };
                if result != 0 {
                    panic!("Failed to set quickack");
                }
            }

            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let self_cloned = cloned_self.clone();
                        let _ = Builder::new()
                            .name("redacted_tcp_geyser".to_string())
                            .spawn(move || {
                                let fd = stream.as_raw_fd();
                                let result = unsafe {
                                    let mut flag: libc::c_int = 1;
                                    libc::setsockopt(
                                        fd,
                                        libc::IPPROTO_TCP,
                                        libc::TCP_NODELAY,
                                        &mut flag as *mut _ as *const _,
                                        std::mem::size_of_val(&flag) as u32,
                                    )
                                };
                                if result != 0 {
                                    return;
                                }
                                #[cfg(target_os = "linux")]
                                {
                                    let quickack: libc::c_int = 1;
                                    let result = unsafe {
                                        libc::setsockopt(
                                            fd,
                                            libc::IPPROTO_TCP,
                                            libc::TCP_QUICKACK,
                                            &quickack as *const _ as *const _,
                                            std::mem::size_of_val(&quickack) as libc::socklen_t,
                                        )
                                    };
                                    if result != 0 {
                                        return;
                                    }    
                                }
                                 

                                let buffer_size: libc::c_int = REDACTED_GEYSER_SERVER_BACKPRESSURE as i32; 
                                let result = unsafe {
                                    libc::setsockopt(
                                        fd,
                                        libc::SOL_SOCKET,
                                        libc::SO_SNDBUF,
                                        &buffer_size as *const _ as *const _,
                                        std::mem::size_of_val(&buffer_size) as libc::socklen_t,
                                    )
                                };

                                if result != 0 {
                                    return;
                                }

                                /* Add the client */
                                if self_cloned
                                    .listener_client_count
                                    .fetch_add(1, Ordering::SeqCst) >= REDACTED_GEYSER_MAX_CLIENTS {
                                    self_cloned
                                        .listener_client_count
                                        .fetch_sub(1, Ordering::SeqCst);
                                    return;
                                }

                                let mut_self = unsafe {
                                    &mut *((&*self_cloned) as *const RedactedGeyserServer
                                        as *mut RedactedGeyserServer)
                                };

                                let mut client_index = None;
                                for i in 0..REDACTED_GEYSER_MAX_CLIENTS {
                                    if mut_self.listener_clients[i] != 0 {
                                        continue;
                                    }
                                    mut_self.listener_clients[i] = stream.as_raw_fd();
                                    client_index = Some(i);

                                    break;
                                }

                                if client_index.is_none() {
                                    self_cloned
                                        .listener_client_count
                                        .fetch_sub(1, Ordering::SeqCst);
                                    return;
                                }

                                let client_index = client_index.unwrap();

                                {
                                    let self_cloned = self_cloned.clone();
                                    Builder::new()
                                        .name("redacted_tcp_geyser_send".to_string())
                                        .spawn(move || {
                                            self_cloned.thread_send(client_index);
                                        })
                                        .unwrap();
                                }

                                self_cloned.thread_recv(stream);
                                mut_self.listener_clients[client_index] = 0; /* This will execute when the client has disconnected */

                                self_cloned
                                    .listener_client_count
                                    .fetch_sub(1, Ordering::SeqCst);
                            });
                    }
                    Err(_) => {
                    }
                }
            }
        })
        .unwrap();

        Ok(())
    }
}

impl Drop for RedactedGeyserServer {
    fn drop(&mut self) {
        for i in 0..REDACTED_GEYSER_MAX_CLIENTS {
            if self.listener_clients[i] != 0 {

                unsafe {
                    libc::close(self.listener_clients[i]);
                }

                self.listener_clients[i] = 0;
            }
        }
    }
}