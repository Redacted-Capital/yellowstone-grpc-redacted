use core::fmt;
use crossbeam_channel::{Receiver, Sender};
use libc::{setsockopt, socklen_t, MSG_NOSIGNAL, SOL_SOCKET, SO_SNDBUF};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::collections::HashSet;
use std::io::Error;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, Builder};
use std::time::{Duration, Instant};

use crate::redacted_memory_pool::RedactedMemoryPool;
use crate::redacted_udp_types::{
    RedactedGeyserError, REDACTED_GEYSER_HEARTBEAT, REDACTED_GEYSER_HEARTBEAT_TIMEOUT,
    REDACTED_GEYSER_MAGIC_GUARD_END, REDACTED_GEYSER_MAGIC_GUARD_START,
    REDACTED_GEYSER_MAX_CLIENTS, REDACTED_GEYSER_MEMORY_POOL_SIZE,
    REDACTED_GEYSER_NOTIFY_ACCOUNT_UPDATE, REDACTED_GEYSER_PACKET_HEADER_SIZE,
    REDACTED_GEYSER_PACKET_MAX_SIZE, REDACTED_GEYSER_SERVER_BACKPRESSURE,
    REDACTED_GEYSER_SERVER_WORK_ORDERS, REDACTED_GEYSER_SET_PROGRAM_CONFIG,
};

pub struct RedactedGeyserServer {
    listener_socket: UdpSocket,

    listener_clients: [libc::sockaddr_in; REDACTED_GEYSER_MAX_CLIENTS],
    listener_client_count: AtomicUsize,

    listener_clients_channels:
        [(Sender<&'static mut [u8]>, Receiver<&'static mut [u8]>); REDACTED_GEYSER_MAX_CLIENTS],

    listener_clients_heartbeats: [Instant; REDACTED_GEYSER_MAX_CLIENTS],

    memory_pool: RedactedMemoryPool,
    geyser_program_list: RwLock<HashSet<Pubkey>>,
}

impl fmt::Debug for RedactedGeyserServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactedGeyserServer")
            .field("listener_socket", &self.listener_socket)
            .field("listener_client_count", &self.listener_client_count)
            .field("listener_clients_channels", &self.listener_clients_channels)
            .field(
                "listener_clients_heartbeats",
                &self.listener_clients_heartbeats,
            )
            .field("memory_pool", &self.memory_pool)
            .field("geyser_program_list", &self.geyser_program_list)
            .finish()
    }
}

impl RedactedGeyserServer {
    pub fn new(address: &str) -> Arc<Self> {
        let memory_pool = RedactedMemoryPool::new(REDACTED_GEYSER_MEMORY_POOL_SIZE);

        let mut client_channels = Vec::with_capacity(REDACTED_GEYSER_MAX_CLIENTS);
        for _ in 0..REDACTED_GEYSER_MAX_CLIENTS {
            let (sender, receiver) = crossbeam_channel::bounded(REDACTED_GEYSER_SERVER_WORK_ORDERS);
            client_channels.push((sender, receiver));
        }

        let listener_socket = UdpSocket::bind(address).unwrap_or_else(|_| {
            panic!("Failed to bind UDP socket to {}", address);
        });

        unsafe {
            Arc::new(Self {
                listener_socket,
                listener_clients: [std::mem::zeroed::<libc::sockaddr_in>();
                    REDACTED_GEYSER_MAX_CLIENTS],
                listener_client_count: AtomicUsize::new(0),
                listener_clients_channels: client_channels.try_into().unwrap(),
                listener_clients_heartbeats: [Instant::now(); REDACTED_GEYSER_MAX_CLIENTS],
                memory_pool,
                geyser_program_list: RwLock::new(HashSet::new()),
            })
        }
    }

    fn handle_set_program_config(self: &Arc<Self>, request_mem: &[u8]) {
        self.geyser_program_list.write().unwrap().clear();

        let mut offset = 0;
        while offset + 32 <= request_mem.len() {
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
        request_type: u8,
        request_mem: &[u8],
    ) -> Result<(), RedactedGeyserError> {
        match request_type {
            REDACTED_GEYSER_SET_PROGRAM_CONFIG => {
                self.handle_set_program_config(request_mem);
            }
            REDACTED_GEYSER_NOTIFY_ACCOUNT_UPDATE => {}
            _ => {}
        }
        Ok(())
    }

    fn create_response(
        self: &Arc<Self>,
        request_type: u8,
        request_length: u32,
        request_mem: &mut [u8],
    ) -> usize {
        request_mem[0] = REDACTED_GEYSER_MAGIC_GUARD_START;
        request_mem[1] = request_type;
        request_mem[2..6].copy_from_slice(
            &(request_length - REDACTED_GEYSER_PACKET_HEADER_SIZE as u32).to_le_bytes(),
        );
        request_mem[request_mem.len() - 1] = REDACTED_GEYSER_MAGIC_GUARD_END;

        REDACTED_GEYSER_PACKET_HEADER_SIZE
    }

    fn send_request(self: &Arc<Self>, data: &'static mut [u8]) -> Result<(), Error> {
        for i in 0..REDACTED_GEYSER_MAX_CLIENTS {
            let client_opt = self.listener_clients[i];
            if client_opt.sin_family == 0 {
                continue;
            }

            unsafe {
                if self.listener_clients_channels[i]
                    .0
                    .try_send(std::ptr::read(&data))
                    .is_err()
                {
                    let mut_self = &mut *((&**self) as *const RedactedGeyserServer
                        as *mut RedactedGeyserServer);
                    mut_self.listener_clients[i] = std::mem::zeroed();

                    self.listener_client_count.fetch_sub(1, Ordering::SeqCst);
                }
            }
        }

        Ok(())
    }

    fn thread_heartbeat(self: &Arc<Self>) {
        loop {
            for i in 0..REDACTED_GEYSER_MAX_CLIENTS {
                if self.listener_clients[i].sin_family == 0 {
                    continue;
                }

                if Instant::now()
                    .duration_since(self.listener_clients_heartbeats[i])
                    .as_secs()
                    > REDACTED_GEYSER_HEARTBEAT_TIMEOUT
                {
                    unsafe {
                        let mut_self = &mut *((&**self) as *const RedactedGeyserServer
                            as *mut RedactedGeyserServer);
                        mut_self.listener_clients[i] = std::mem::zeroed();
                    }
                }
            }

            thread::sleep(Duration::from_secs(1));
        }
    }

    fn thread_send(self: &Arc<Self>, client_index: usize) {
        let socket_fd = self.listener_socket.as_raw_fd();
        self.listener_client_count.fetch_add(1, Ordering::SeqCst);

        'outer: loop {
            let work_order = match self.listener_clients_channels[client_index].1.recv() {
                Ok(w) => w,
                Err(_) => {
                    break;
                }
            };

            let addr = &self.listener_clients[client_index];
            if addr.sin_family == 0 {
                break;
            }

            loop {
                let sent = unsafe {
                    libc::sendto(
                        socket_fd,
                        work_order.as_ptr() as *const c_void,
                        work_order.len(),
                        MSG_NOSIGNAL,
                        addr as *const libc::sockaddr_in as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_in>() as socklen_t,
                    )
                };

                if sent < 0 {
                    if let Some(errno) = Error::last_os_error().raw_os_error() {
                        if errno == libc::EWOULDBLOCK {
                            std::thread::yield_now();
                            continue;
                        }
                    }
                    break 'outer;
                }

                break;
            }
        }

        unsafe {
            let mut_self =
                &mut *((&**self) as *const RedactedGeyserServer as *mut RedactedGeyserServer);

            mut_self.listener_clients[client_index] = std::mem::zeroed();
            self.listener_client_count.fetch_sub(1, Ordering::SeqCst);
        }
    }

    pub fn send_account_update(
        self: &Arc<Self>,
        pubkey: &[u8],
        signature: Option<&Signature>,
        slot: u64,
        lamports: u64,
        data: &[u8],
        owner: &Pubkey,
        executable: bool,
        rent_epoch: u64,
        write_version: u64,
        is_sandwich: bool,
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

        let mut total_size = 1     // start magic
            + 1                           // request type
            + 4                           // length
            + 32                          // pubkey
            + 1                           // presence of signature
            + 8 + 8 + 8                   // slot, lamports, data_len
            + data.len()
            + 32                          // owner
            + 1                           // executable
            + 8                           // rent_epoch
            + 8                           // write_version
            + 1                           // is_sandwich
            + 1; // end magic

        if signature.is_some() {
            total_size += 64; // signature bytes
        }

        let request_mem = self.memory_pool.alloc(total_size);
        let mut offset = self.create_response(
            REDACTED_GEYSER_NOTIFY_ACCOUNT_UPDATE,
            total_size as u32,
            request_mem,
        );

        request_mem[offset..offset + 32].copy_from_slice(pubkey.as_ref());
        offset += 32;

        if let Some(signature) = signature {
            request_mem[offset] = 1;
            offset += 1;
            request_mem[offset..offset + 64].copy_from_slice(signature.as_ref());
            offset += 64;
        } else {
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

        self.send_request(request_mem)?;

        Ok(())
    }

    pub fn start_server(self: &Arc<Self>) -> Result<(), Error> {
        let fd = self.listener_socket.as_raw_fd();
        unsafe {
            let buffer_size: libc::c_int = REDACTED_GEYSER_SERVER_BACKPRESSURE as i32;
            let res = setsockopt(
                fd,
                SOL_SOCKET,
                SO_SNDBUF,
                &buffer_size as *const _ as *const _,
                std::mem::size_of_val(&buffer_size) as socklen_t,
            );
            if res != 0 {
                panic!("Failed to set SO_SNDBUF on UDP socket");
            }
        }

        {
            let cloned_self = self.clone();
            Builder::new()
                .name("redacted_udp_geyser_listener".to_string())
                .spawn(move || {
                    let server = cloned_self;
                    let mut recv_buf = vec![0u8; REDACTED_GEYSER_PACKET_MAX_SIZE as usize];

                    loop {
                        let Ok((len, addr)) = server.listener_socket.recv_from(&mut recv_buf)
                        else {
                            continue;
                        };

                        if len < REDACTED_GEYSER_PACKET_HEADER_SIZE {
                            continue;
                        }

                        let packet_buf =
                            unsafe { std::slice::from_raw_parts_mut(recv_buf.as_mut_ptr(), len) };

                        if packet_buf[0] != REDACTED_GEYSER_MAGIC_GUARD_START {
                            continue;
                        }

                        let request_type = packet_buf[1];
                        let payload_len = u32::from_le_bytes([
                            packet_buf[2],
                            packet_buf[3],
                            packet_buf[4],
                            packet_buf[5],
                        ]);

                        if payload_len > REDACTED_GEYSER_PACKET_MAX_SIZE {
                            continue;
                        }

                        if len != REDACTED_GEYSER_PACKET_HEADER_SIZE + payload_len as usize {
                            continue;
                        }

                        if packet_buf[packet_buf.len() - 1] != REDACTED_GEYSER_MAGIC_GUARD_END {
                            continue;
                        }

                        if request_type == REDACTED_GEYSER_HEARTBEAT {
                            let addr = sockaddr_ip_addr_port(&addr);
                            for i in 0..REDACTED_GEYSER_MAX_CLIENTS {
                                if server.listener_clients[i].sin_family == 0 {
                                    continue;
                                }

                                if server.listener_clients[i].sin_addr.s_addr == addr.0
                                    && server.listener_clients[i].sin_port == addr.1
                                {
                                    let mut_self = unsafe {
                                        &mut *((&*server) as *const RedactedGeyserServer
                                            as *mut RedactedGeyserServer)
                                    };
                                    mut_self.listener_clients_heartbeats[i] = Instant::now();
                                    break;
                                }
                            }
                            continue;
                        }

                        let _ = server.handle_request(request_type, &mut packet_buf[6..]);

                        if server.listener_client_count.load(Ordering::SeqCst)
                            < REDACTED_GEYSER_MAX_CLIENTS
                        {
                            let mut_self = unsafe {
                                &mut *((&*server) as *const RedactedGeyserServer
                                    as *mut RedactedGeyserServer)
                            };

                            if let Some(addr) = sockaddr_from_std(&addr) {
                                #[cfg(target_os = "linux")]
                                unsafe {
                                    let sock_addr_ptr = &addr as *const libc::sockaddr_in;
                                    if !mut_self.listener_clients.iter().any(|c| {
                                        c.sin_addr == (*sock_addr_ptr).sin_addr
                                            && c.sin_family == (*sock_addr_ptr).sin_family
                                            && c.sin_port == (*sock_addr_ptr).sin_port
                                    }) {
                                        for i in 0..REDACTED_GEYSER_MAX_CLIENTS {
                                            if mut_self.listener_clients[i].sin_family == 0 {
                                                mut_self.listener_clients[i] = *sock_addr_ptr;
                                                mut_self.listener_clients_heartbeats[i] =
                                                    Instant::now();

                                                let self_cloned = server.clone();
                                                Builder::new()
                                                    .name(format!("redacted_udp_geyser_send_{}", i))
                                                    .spawn(move || {
                                                        self_cloned.thread_send(i);
                                                    })
                                                    .unwrap();

                                                break;
                                            }
                                        }
                                    }
                                }

                                #[cfg(not(target_os = "linux"))]
                                unsafe {
                                    let sock_addr_ptr = &addr as *const libc::sockaddr_in;
                                    if !mut_self.listener_clients.iter().any(|c| {
                                        c.sin_addr.s_addr == (*sock_addr_ptr).sin_addr.s_addr
                                            && c.sin_family == (*sock_addr_ptr).sin_family
                                            && c.sin_port == (*sock_addr_ptr).sin_port
                                    }) {
                                        for i in 0..REDACTED_GEYSER_MAX_CLIENTS {
                                            if mut_self.listener_clients[i].sin_family == 0 {
                                                mut_self.listener_clients[i] = *sock_addr_ptr;
                                                mut_self.listener_clients_heartbeats[i] =
                                                    Instant::now();

                                                let self_cloned = server.clone();
                                                Builder::new()
                                                    .name(format!("redacted_udp_geyser_send_{}", i))
                                                    .spawn(move || {
                                                        self_cloned.thread_send(i);
                                                    })
                                                    .unwrap();

                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                })?;
        }
        {
            let cloned_self = self.clone();
            Builder::new()
                .name("redacted_udp_geyser_heartbeat".to_string())
                .spawn(move || {
                    cloned_self.thread_heartbeat();
                })?;
        }

        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
}

fn sockaddr_from_std(addr: &SocketAddr) -> Option<libc::sockaddr_in> {
    #[cfg(not(target_os = "linux"))]
    match addr {
        SocketAddr::V4(a4) => Some(libc::sockaddr_in {
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as u8,
            sin_port: a4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(a4.ip().octets()),
            },
            sin_zero: [0; 8],
        }),
        SocketAddr::V6(_) => None,
    }
    #[cfg(target_os = "linux")]
    match addr {
        SocketAddr::V4(a4) => Some(libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: a4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(a4.ip().octets()),
            },
            sin_zero: [0; 8],
        }),
        SocketAddr::V6(_) => None,
    }
}

fn sockaddr_ip_addr_port(addr: &SocketAddr) -> (u32, u16) {
    match addr {
        SocketAddr::V4(a4) => (u32::from_ne_bytes(a4.ip().octets()), a4.port().to_be()),
        SocketAddr::V6(_) => (0, 0),
    }
}

impl Drop for RedactedGeyserServer {
    fn drop(&mut self) {
        unsafe {
            self.listener_clients = std::mem::zeroed();
        }
    }
}
