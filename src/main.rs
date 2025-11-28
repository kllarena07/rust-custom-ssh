use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
};

use rand::RngCore;

fn create_ssh_packet(payload: Vec<u8>) -> Vec<u8> {
    // SSH packet format: [packet_length][padding_length][payload][padding][MAC]
    // packet_length: 4 bytes, includes padding_length + payload + padding
    // padding_length: 1 byte, number of padding bytes
    // padding: random bytes to make total size a multiple of 8 or cipher block size

    let block_size = 8; // minimum block size for SSH
    let min_padding = 4;

    // Calculate required padding
    let total_size = 1 + payload.len(); // padding_length + payload
    let padding_needed = if total_size % block_size == 0 {
        min_padding
    } else {
        min_padding + (block_size - (total_size % block_size))
    };

    let packet_length = 1 + payload.len() + padding_needed;

    let mut packet: Vec<u8> = vec![];

    // Packet length (4 bytes, big endian)
    packet.extend_from_slice(&(packet_length as u32).to_be_bytes());

    // Padding length (1 byte)
    packet.push(padding_needed as u8);

    // Payload
    packet.extend_from_slice(&payload);

    // Padding (random bytes)
    let mut rng = rand::rng();
    for _ in 0..padding_needed {
        packet.push(rng.next_u32() as u8);
    }

    packet
}

fn from_ssh_packet(packet: &[u8]) -> Result<Vec<u8>, &'static str> {
    // return the ssh packet payload
    // SSH packet format: [packet_length][padding_length][payload][padding][MAC]
    // packet_length: 4 bytes, includes padding_length + payload + padding
    // padding_length: 1 byte, number of padding bytes

    if packet.len() < 5 {
        return Err("Packet too short");
    }

    // Extract packet length (first 4 bytes)
    let packet_length = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]) as usize;

    // Extract padding length (5th byte)
    let padding_length = packet[4] as usize;

    // Validate packet length
    if packet_length + 4 != packet.len() {
        return Err("Invalid packet length");
    }

    // Calculate payload size: total_packet_size - 4(length) - 1(padding_length) - padding_length
    let payload_size = packet_length - 1 - padding_length;

    // Extract payload (starts after 5 bytes: 4 for length, 1 for padding_length)
    let payload_start = 5;
    let payload_end = payload_start + payload_size;

    if payload_end > packet.len() {
        return Err("Payload extends beyond packet");
    }

    Ok(packet[payload_start..payload_end].to_vec())
}

fn to_name_list(value: &str) -> Vec<u8> {
    // A string containing a comma-separated list of names.
    // https://datatracker.ietf.org/doc/html/rfc4251#section-5
    // Examples:
    // value                      representation (hex)
    // -----                      --------------------
    // (), the empty name-list    00 00 00 00
    // ("zlib")                   00 00 00 04 7a 6c 69 62
    // ("zlib,none")              00 00 00 09 7a 6c 69 62 2c 6e 6f 6e 65

    let len = (value.len() as u32).to_be_bytes();

    let mut bytes: Vec<u8> = vec![];

    for b in len {
        bytes.push(b);
    }

    for b in value.as_bytes().to_vec() {
        bytes.push(b);
    }

    bytes
}

fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    println!("{:?}", stream);

    // Send identification string first
    const IDENTIFICATION_STRING: &str = "SSH-2.0-rust_custom_ssh_1.0\r\n";
    stream.write_all(IDENTIFICATION_STRING.as_bytes())?;
    stream.flush()?;

    // Read client identification string
    let mut buf = [0u8; 256];
    let mut identification_buf: Vec<u8> = vec![];

    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }

        identification_buf.extend_from_slice(&buf[..n]);

        // Check if we received the complete identification string (ends with \r\n)
        if identification_buf.ends_with(b"\r\n") {
            break;
        }
    }

    println!(
        "Client identification: {}",
        String::from_utf8_lossy(&identification_buf)
    );

    // Build KEXINIT packet
    let mut kex_payload: Vec<u8> = vec![];

    // SSH_MSG_KEXINIT
    kex_payload.push(20u8);

    // byte[16], cookie (random bytes)
    let mut cookie: [u8; 16] = [0; 16];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut cookie);
    kex_payload.extend_from_slice(&cookie);

    //  name-list    kex_algorithms
    const SUPPORTED_KEX_ALGORITHMS: &str = "curve25519-sha256";
    kex_payload.extend_from_slice(&to_name_list(SUPPORTED_KEX_ALGORITHMS));

    //  name-list    server_host_key_algorithms
    const SERVER_HOST_KEY_ALGORITHMS: &str = "ssh-ed25519";
    kex_payload.extend_from_slice(&to_name_list(SERVER_HOST_KEY_ALGORITHMS));

    //  name-list    encryption_algorithms_client_to_server (ciphers)
    const CS_CIPHERS: &str = "chacha20-poly1305@openssh.com";
    kex_payload.extend_from_slice(&to_name_list(CS_CIPHERS));

    //  name-list    encryption_algorithms_server_to_client (ciphers)
    const SC_CIPHERS: &str = "chacha20-poly1305@openssh.com";
    kex_payload.extend_from_slice(&to_name_list(SC_CIPHERS));

    //  name-list    mac_algorithms_client_to_server
    const CS_MAC_ALGOS: &str = "hmac-sha2-256";
    kex_payload.extend_from_slice(&to_name_list(CS_MAC_ALGOS));

    //  name-list    mac_algorithms_server_to_client
    const SC_MAC_ALGOS: &str = "hmac-sha2-256";
    kex_payload.extend_from_slice(&to_name_list(SC_MAC_ALGOS));

    //  name-list    compression_algorithms_client_to_server
    const CS_COMP_ALGOS: &str = "none";
    kex_payload.extend_from_slice(&to_name_list(CS_COMP_ALGOS));

    //  name-list    compression_algorithms_server_to_client
    const SC_COMP_ALGOS: &str = "none";
    kex_payload.extend_from_slice(&to_name_list(SC_COMP_ALGOS));

    //  name-list    languages_client_to_server
    kex_payload.extend_from_slice(&to_name_list("")); // NONE

    //  name-list    languages_server_to_client
    kex_payload.extend_from_slice(&to_name_list("")); // NONE

    //  boolean      first_kex_packet_follows
    kex_payload.push(0); // false

    //  uint32       reserved (0)
    kex_payload.extend_from_slice(&0u32.to_be_bytes());

    // Create and send proper SSH packet
    let kex_packet = create_ssh_packet(kex_payload);
    stream.write_all(&kex_packet)?;
    stream.flush()?;

    println!("KEXINIT packet sent");

    // Continue reading packets from client
    loop {
        let mut packet_buf = [0u8; 32768];
        let n = stream.read(&mut packet_buf)?;

        if n == 0 {
            return Ok(());
        }

        println!("Received {} bytes from client", n);
        std::io::stdout().write_all(&packet_buf[..n])?;
        std::io::stdout().flush()?;
    }

    // Next step is the Diffie-Hellman Key Exchange
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:3022")?;

    for stream in listener.incoming() {
        if let Err(e) = handle_client(stream?) {
            eprintln!("\n\nError: {}", e);
        }
    }

    Ok(())
}
