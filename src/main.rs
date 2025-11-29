use std::{
    fs::File,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha256};

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

fn read_ssh_packet(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut packet_buf = Vec::new();
    let mut temp_buf = [0u8; 1024];

    loop {
        let n = stream.read(&mut temp_buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection closed",
            ));
        }
        packet_buf.extend_from_slice(&temp_buf[..n]);

        // Try to parse the packet to see if we have a complete one
        if packet_buf.len() >= 4 {
            let packet_length =
                u32::from_be_bytes([packet_buf[0], packet_buf[1], packet_buf[2], packet_buf[3]])
                    as usize;
            let expected_size = packet_length + 4;

            if packet_buf.len() >= expected_size {
                break;
            }
        }
    }

    Ok(packet_buf)
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

fn to_ssh_string(data: &[u8]) -> Vec<u8> {
    // SSH string format: [4-byte length][data bytes]
    let len = (data.len() as u32).to_be_bytes();
    let mut result = len.to_vec();
    result.extend_from_slice(data);
    result
}

fn to_mpint(value: &[u8]) -> Vec<u8> {
    // Multiple precision integer in two's complement format
    // Format: [4-byte length][data bytes]
    // Examples:
    // value (hex)        representation (hex)
    // -----------        --------------------
    // 0                  00 00 00 00
    // 9a378f9b2e332a7    00 00 00 08 09 a3 78 f9 b2 e3 32 a7
    // 80                 00 00 00 02 00 80
    // -1234              00 00 00 02 ed cc
    // -deadbeef          00 00 00 05 ff 21 52 41 11

    // Remove unnecessary leading bytes
    let mut trimmed = value.to_vec();

    // Remove leading 0x00 bytes (for positive numbers)
    while trimmed.len() > 1 && trimmed[0] == 0 && (trimmed[1] & 0x80) == 0 {
        trimmed.remove(0);
    }

    // Check if most significant bit would be set (indicating negative)
    // If so, prepend a zero byte to ensure it's interpreted as positive
    if !trimmed.is_empty() && (trimmed[0] & 0x80) != 0 {
        trimmed.insert(0, 0);
    }

    // Special case: zero should have zero bytes of data
    if trimmed.iter().all(|&b| b == 0) {
        trimmed.clear();
    }

    // Length prefix (4 bytes, big endian)
    let len = (trimmed.len() as u32).to_be_bytes();
    let mut result = len.to_vec();
    result.extend_from_slice(&trimmed);

    result
}

fn from_mpint(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    // Extract multiple precision integer from SSH format
    // Format: [4-byte length][data bytes]

    if data.len() < 4 {
        return Err("MPINT too short");
    }

    // Extract length (first 4 bytes)
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    // Check if we have enough data
    if data.len() < 4 + len {
        return Err("MPINT length exceeds data");
    }

    // Extract the actual integer bytes
    let int_bytes = &data[4..4 + len];

    Ok(int_bytes.to_vec())
}

// Group14 2048-bit prime from RFC 3526
fn get_group14_prime() -> BigUint {
    // This is the 2048-bit MODP Group from RFC 3526, Section 3
    let prime_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF";

    BigUint::parse_bytes(prime_hex.as_bytes(), 16).unwrap()
}

fn load_host_key() -> io::Result<(SigningKey, VerifyingKey)> {
    let mut private_key_bytes = [0u8; 32];
    let mut file = File::open("authorized_keys/ssh_host_ed25519_key")
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to open host key file 'authorized_keys/ssh_host_ed25519_key': {}. Please run 'ssh-keygen -t ed25519 -f authorized_keys/ssh_host_ed25519_key -N \"\"' to generate the host key.", e)))?;
    file.read_exact(&mut private_key_bytes)?;

    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

fn handle_client(mut stream: TcpStream) -> io::Result<()> {
    println!("{:?}", stream);

    // Send identification string first
    const IDENTIFICATION_STRING: &str = "SSH-2.0-rust_custom_ssh_1.0\r\n";
    stream.write_all(IDENTIFICATION_STRING.as_bytes())?;
    stream.flush()?;
    let server_ident_str = IDENTIFICATION_STRING.trim_end_matches("\r\n");

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

    let client_ident_string = String::from_utf8_lossy(&identification_buf);
    let client_ident_str = client_ident_string.trim_end_matches("\r\n");
    println!("Client identification: {}", client_ident_str);

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
    const SUPPORTED_KEX_ALGORITHMS: &str = "diffie-hellman-group14-sha256";
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
    let kex_packet = create_ssh_packet(kex_payload.clone());
    stream.write_all(&kex_packet)?;
    stream.flush()?;

    println!("KEXINIT packet sent");

    // Receive client's KEXINIT packet
    let packet_buf = read_ssh_packet(&mut stream)?;
    let client_kexinit_payload =
        from_ssh_packet(&packet_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    println!(
        "Received client KEXINIT payload: {:?}",
        client_kexinit_payload
    );

    // Next step is the Diffie-Hellman Key Exchange
    let packet_buf = read_ssh_packet(&mut stream)?;
    println!("Received bytes: {:?}", packet_buf);

    let parsed =
        from_ssh_packet(&packet_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    println!("Extracted SSH packet payload: {:?}", parsed);

    let mpint_data = &parsed[1..]; // Skip packet type 30
    let client_public_key = from_mpint(mpint_data).unwrap();
    println!("Client Public Key: {:?}", client_public_key);

    // 1. Generate a secret exponent b
    let mut rng = rand::rng();
    let prime = get_group14_prime();
    let generator = BigUint::from(2u32);

    // Generate random secret exponent b (should be at least 2*bits of security)
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let secret_b = BigUint::from_bytes_be(&secret_bytes);

    // 2. Compute public key B = g^b mod p
    let server_public_key_b = generator.modpow(&secret_b, &prime);

    // Convert client public key A to BigUint
    let client_public_key_a = BigUint::from_bytes_be(&client_public_key);

    // 3. Compute shared secret K = A^b mod p
    let shared_secret_k = client_public_key_a.modpow(&secret_b, &prime);

    println!(
        "Server public key B: {:?}",
        server_public_key_b.to_bytes_be()
    );
    println!("Shared secret K: {:?}", shared_secret_k.to_bytes_be());

    // Generate host key
    let (host_private_key, host_public_key) = load_host_key()?;

    // 4. Send KEXDH_REPLY with B, host key, and signature of the exchange hash
    let mut kexdh_reply_payload: Vec<u8> = vec![];

    // SSH_MSG_KEXDH_REPLY (type 31)
    kexdh_reply_payload.push(31u8);

    // Server host key blob (ssh-ed25519 format)
    let host_key_bytes = host_public_key.as_bytes();
    let mut host_key_blob = Vec::new();
    host_key_blob.extend_from_slice(&to_name_list("ssh-ed25519"));
    host_key_blob.extend_from_slice(&(host_key_bytes.len() as u32).to_be_bytes());
    host_key_blob.extend_from_slice(host_key_bytes);
    kexdh_reply_payload.extend_from_slice(&to_ssh_string(&host_key_blob));

    // Server public key B (as MPINT)
    let server_public_b_bytes = server_public_key_b.to_bytes_be();
    kexdh_reply_payload.extend_from_slice(&to_mpint(&server_public_b_bytes));

    // Shared secret H (exchange hash) - simplified for now
    // In real implementation, this should be SHA256 of all KEX parameters
    let mut hasher = Sha256::new();
    hasher.update(to_ssh_string(client_ident_str.as_bytes())); // 1. Client ID
    hasher.update(to_ssh_string(server_ident_str.as_bytes())); // 2. Server ID
    hasher.update(to_ssh_string(&client_kexinit_payload)); // 3. Client KEXINIT
    hasher.update(to_ssh_string(&kex_payload)); // 4. Server KEXINIT
    hasher.update(to_ssh_string(&host_key_blob)); // 5. Host key
    hasher.update(to_mpint(&client_public_key)); // 6. Client public key A
    hasher.update(to_mpint(&server_public_b_bytes)); // 7. Server public key B
    hasher.update(to_mpint(&shared_secret_k.to_bytes_be())); // 8. Shared secret K
    let exchange_hash = hasher.finalize();

    // Sign the exchange hash with host private key
    let signature = host_private_key.sign(&exchange_hash);
    let signature_bytes = signature.to_bytes();

    // Add signature blob (ssh-ed25519 format)
    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&to_name_list("ssh-ed25519"));
    signature_blob.extend_from_slice(&(signature_bytes.len() as u32).to_be_bytes());
    signature_blob.extend_from_slice(&signature_bytes);
    kexdh_reply_payload.extend_from_slice(&to_ssh_string(&signature_blob));

    // Create and send KEXDH_REPLY packet
    let kexdh_reply_packet = create_ssh_packet(kexdh_reply_payload);
    println!("KEXDH_REPLY packet: {:02x?}", kexdh_reply_packet);
    stream.write_all(&kexdh_reply_packet)?;
    stream.flush()?;

    println!("KEXDH_REPLY packet sent");

    // Receive client's SSH2_MSG_NEWKEYS packet for rekey
    let rekey_packet_buf = read_ssh_packet(&mut stream)?;
    let client_kexinit_payload = from_ssh_packet(&rekey_packet_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    println!(
        "Received client KEXINIT payload for rekey: {:?}",
        client_kexinit_payload
    );
    println!("The payload should be 21. This means SSH2_MSG_NEWKEYS according to RFC 4253");

    // SSH2_MSG_NEWKEYS packet
    let kex_payload_rekey: Vec<u8> = vec![21u8];

    let rekey_kex_packet = create_ssh_packet(kex_payload_rekey);
    stream.write_all(&rekey_kex_packet)?;
    stream.flush()?;

    loop {}

    // Ok(())
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
