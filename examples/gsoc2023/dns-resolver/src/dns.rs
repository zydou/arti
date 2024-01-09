//! Houses the DNS-specifc code, including the structs that we pack the bytes
//! into and suitable traits and implementations to convert to and from bytes
//! and structs
//!
//! ### Disclaimer
//! This is a very barebones DNS client implementation. It hard-codes a lot of
//! values and is intended only for demonstration purposes on how even custom
//! protocols over TCP can be tunnelled through Tor. It is not meant for any
//! real production usage.
use anyhow::Result;
use std::fmt::Display;
use thiserror::Error;
use tracing::{debug, error};

#[derive(Error, Debug)]
#[error("Failed to parse bytes into struct!")]
/// Generic error we return if we fail to parse bytes into the struct
struct FromBytesError;

#[derive(Error, Debug)]
#[error("Invalid domain name passed")]
/// Error we return if a bad domain name is passed
pub struct DomainError;

/// Hardcoded DNS server, stored as (&str, u16) detailing host and port
pub const DNS_SERVER: (&str, u16) = ("1.1.1.1", 53);

/// Default value for QTYPE field
const QTYPE: u16 = 0x0001;
/// Default value for QCLASS field
const QCLASS: u16 = 0x0001;

/// Used to convert struct to raw bytes to be sent over the network
///
/// Example:
/// ```
/// // We have some struct S that implements this trait
/// let s = S::new();
/// // This prints the raw bytes as debug output
/// dbg!("{}", s.as_bytes());
/// ```
pub trait AsBytes {
    /// Return a `Vec<u8>` of the same information stored in struct
    ///
    /// This is ideal to convert typed values into raw bytes to be sent
    /// over the network.
    fn as_bytes(&self) -> Vec<u8>;
}

/// Used to convert raw bytes representation into a Rust struct
///
/// Example:
/// ```
/// let mut buf: Vec<u8> = Vec::new();
/// // Read the response from a stream
/// stream.read_to_end(&mut buf).await.unwrap();
/// // Interpret the response into a struct S
/// let resp = S::from_bytes(&buf);
/// ```
///
/// In the above code, `resp` is `Option<Box<S>>` type, so you will have to
/// deal with the `None` value appropriately. This helps denote invalid
/// situations, ie, parse failures
///
/// You will have to interpret each byte and convert it into each field
/// of your struct yourself when implementing this trait.
pub trait FromBytes {
    /// Convert two u8's into a u16
    ///
    /// It is just a thin wrapper over [u16::from_be_bytes()]
    fn u8_to_u16(upper: u8, lower: u8) -> u16 {
        let bytes = [upper, lower];
        u16::from_be_bytes(bytes)
    }
    /// Convert four u8's contained in a slice into a u32
    ///
    /// It is just a thin wrapper over [u32::from_be_bytes()] but also deals
    /// with converting &\[u8\] (u8 slice) into [u8; 4] (a fixed size array of u8)
    fn u8_to_u32(bytes_slice: &[u8]) -> Result<u32> {
        let bytes: [u8; 4] = bytes_slice.try_into()?;
        Ok(u32::from_be_bytes(bytes))
    }
    /// Try converting given bytes into the struct
    ///
    /// Returns an `Option<Box>` of the struct which implements
    /// this trait to help denote parsing failures
    fn from_bytes(bytes: &[u8]) -> Result<Box<Self>>;
}

/// Report length of the struct as in byte stream
///
/// Note that this doesn't mean length of struct
///
/// It is simply used to denote how long the struct is if it were
/// sent over the wire
trait Len {
    /// Report length of the struct as in byte stream
    fn len(&self) -> usize;
}

/// DNS Header to be used by both Query and Response
///
/// The default values chosen are from the perspective of the client
// TODO: For server we will have to interpret given values
struct Header {
    /// Random 16 bit number used to identify the DNS request
    identification: u16,
    /// Set of fields packed together into one 16 bit number
    ///
    /// Refer to RFC 1035 for more info, but here's a small
    /// layout of what is packed into this row:
    ///
    ///
    ///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// TODO: don't rely on cryptic packed bits
    packed_second_row: u16, // set to 0x100
    /// Number of questions we have
    ///
    /// Here, we set it to 1 since we only ask about one hostname in a query
    qdcount: u16, // set to 1 since we have 1 question
    /// Number of answers we have
    ///
    /// For a query it will be zero, for a response hopefully it is >= 1
    ancount: u16, // set to 0 since client doesn't have answers
    /// Refer to RFC 1035 section 4.1.1, NSCOUNT
    nscount: u16, // set to 0
    /// Refer to RFC 1035 section 4.1.1, ARCOUNT
    arcount: u16, // set to 0
}

// Ugly, repetitive code to convert all six 16-bit fields into Vec<u8>
impl AsBytes for Header {
    fn as_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(14);
        // These 2 bytes store size of the rest of the payload (including header)
        // Right now it denotes 51 byte size packet, excluding these 2 bytes
        // We will change this when we know the size of Query
        v.push(0x00);
        v.push(0x33);
        // Just break u16 into [u8, u8] array and copy into vector
        v.extend_from_slice(&u16::to_be_bytes(self.identification));
        v.extend_from_slice(&u16::to_be_bytes(self.packed_second_row));
        v.extend_from_slice(&u16::to_be_bytes(self.qdcount));
        v.extend_from_slice(&u16::to_be_bytes(self.ancount));
        v.extend_from_slice(&u16::to_be_bytes(self.nscount));
        v.extend_from_slice(&u16::to_be_bytes(self.arcount));
        v
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ID: 0x{:x}", self.identification)?;
        writeln!(f, "Flags: 0x{:x}", self.packed_second_row)?;
        writeln!(f, "QDCOUNT: 0x{:x}", self.qdcount)?;
        writeln!(f, "ANCOUNT: 0x{:x}", self.ancount)?;
        writeln!(f, "NSCOUNT: 0x{:x}", self.nscount)?;
        writeln!(f, "ARCOUNT: 0x{:x}", self.arcount)?;
        Ok(())
    }
}

impl FromBytes for Header {
    fn from_bytes(bytes: &[u8]) -> Result<Box<Self>> {
        debug!("Parsing the header");
        let packed_second_row = Header::u8_to_u16(bytes[2], bytes[3]);
        // 0x8180 denotes we have a response to a standard query,
        // that isn't truncated, and has recursion requested to a server
        // that can do recursion, with some bits reserved for future use
        // and some that are not relevant for our purposes
        if packed_second_row == 0x8180 {
            debug!("Correct flags set in response");
        } else {
            error!(
                "Incorrect flags set in response, we got {}",
                packed_second_row
            );
            return Err(FromBytesError.into());
        }
        // These offsets were determined by looking at RFC 1035
        Ok(Box::new(Header {
            identification: Header::u8_to_u16(bytes[0], bytes[1]),
            packed_second_row,
            qdcount: Header::u8_to_u16(bytes[4], bytes[5]),
            ancount: Header::u8_to_u16(bytes[6], bytes[7]),
            nscount: Header::u8_to_u16(bytes[8], bytes[9]),
            arcount: Header::u8_to_u16(bytes[10], bytes[11]),
        }))
    }
}

/// The actual query we will send to a DNS server
///
/// For now A records are fetched only
// TODO: add support for different records to be fetched
pub struct Query {
    /// Header of the DNS packet, see [Header] for more info
    header: Header,
    /// The domain name, stored as a `Vec<u8>`
    ///
    /// When we call [Query::from_bytes()], `qname` is automatically
    /// converted into string stored in a `Vec<u8>` instead of the raw
    /// byte format used for `qname`
    qname: Vec<u8>, // domain name
    /// Denotes the type of record to get.
    ///
    /// Here we set to 1 to get an A record, ie, IPv4
    qtype: u16, // set to 0x0001 for A records
    /// Denotes the class of the record
    ///
    /// Here we set to 1 to get an Internet address
    qclass: u16, // set to 1 for Internet addresses
}

impl AsBytes for Query {
    fn as_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        let header_bytes = self.header.as_bytes();
        v.extend(header_bytes);
        v.extend(&self.qname);
        v.extend_from_slice(&u16::to_be_bytes(self.qtype));
        v.extend_from_slice(&u16::to_be_bytes(self.qclass));
        // Now that the packet is ready, we can calculate size and set that in
        // first two octets
        // Subtract 2 since these first 2 bits are never counted when reporting
        // length like this
        let len_bits = u16::to_be_bytes((v.len() - 2) as u16);
        v[0] = len_bits[0];
        v[1] = len_bits[1];
        v
    }
}

impl Len for Query {
    fn len(&self) -> usize {
        // extra 1 is for compensating for how we
        // use one byte more to store length of domain name
        12 + 1 + self.qname.len() + 2 + 2
    }
}

impl FromBytes for Query {
    // FIXME: the name struct isn't stored as it was sent over the wire
    fn from_bytes(bytes: &[u8]) -> Result<Box<Self>> {
        let header = *Header::from_bytes(&bytes[..12])?;
        if bytes.len() < 12 {
            error!("Mismatch between expected number of bytes and given number of bytes!");
            return Err(FromBytesError.into());
        }
        // Parse name
        let mut name = String::new();
        // 12 represents size of Header, which we have already parsed, or errored out of
        let mut lastnamebyte = 12;
        loop {
            // bytes[lastnamebytes] denotes the prefix length, we read that many bytes into name
            let start = lastnamebyte + 1;
            let end = start + bytes[lastnamebyte] as usize;
            name.extend(std::str::from_utf8(&bytes[start..end]));
            lastnamebyte = end;
            if lastnamebyte >= bytes.len() || bytes[lastnamebyte] == 0 {
                // End of domain name, proceed to parse further fields
                debug!("Reached end of name, moving on to parse other fields");
                lastnamebyte += 1;
                break;
            }
            name.push('.');
        }
        // These offsets were determined by looking at RFC 1035
        Ok(Box::new(Self {
            header,
            qname: name.as_bytes().to_vec(),
            qtype: Query::u8_to_u16(bytes[lastnamebyte], bytes[lastnamebyte + 1]),
            qclass: Query::u8_to_u16(bytes[lastnamebyte + 2], bytes[lastnamebyte + 3]),
        }))
    }
}

/// A struct which represents one RR
struct ResourceRecord {
    /// Denotes the record type
    ///
    /// It is similar to [Query::qtype]
    rtype: u16, // same as in Query
    /// Denotes the class of the record
    ///
    /// It is similar to [Query::qclass]
    class: u16, // same as in Query
    /// The TTL denotes the amount of time in seconds we can cache the result
    ///
    /// After the TTL expires, we have to make a fresh request since this
    /// answer is not guaranteed to be correct
    ttl: u32, // number of seconds to cache the result
    /// Denotes the length of data
    ///
    /// For this implementation we only request IPv4 addresses, so its value
    /// will be 4.
    rdlength: u16, // Length of RDATA
    /// The actual answer we need
    ///
    /// It is an IPv4 address for us in this case
    rdata: [u8; 4], // IP address
}

impl Len for ResourceRecord {
    // return number of bytes it consumes
    fn len(&self) -> usize {
        let mut size = 0;
        size += 2; // name, even though we don't store it here
        size += 2; // rtype
        size += 2; // class
        size += 4; // ttl
        size += 2; // rdlength
        size += 4; // rdata
        size
    }
}

impl FromBytes for ResourceRecord {
    fn from_bytes(bytes: &[u8]) -> Result<Box<Self>> {
        let lastnamebyte = 1;
        let mut rdata = [0u8; 4];
        if bytes.len() < 15 {
            return Err(FromBytesError.into());
        }
        // Copy over IP address into rdata
        rdata.copy_from_slice(&bytes[lastnamebyte + 10..lastnamebyte + 14]);
        // These offsets were determined by looking at RFC 1035
        Ok(Box::new(Self {
            rtype: ResourceRecord::u8_to_u16(bytes[lastnamebyte], bytes[lastnamebyte + 1]),
            class: ResourceRecord::u8_to_u16(bytes[lastnamebyte + 2], bytes[lastnamebyte + 3]),
            ttl: ResourceRecord::u8_to_u32(&bytes[lastnamebyte + 4..lastnamebyte + 8])?,
            rdlength: Response::u8_to_u16(bytes[lastnamebyte + 8], bytes[lastnamebyte + 9]),
            rdata,
        }))
    }
}

impl Display for ResourceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "RR record type: 0x{:x}", self.rtype)?;
        writeln!(f, "RR class: 0x{:x}", self.class)?;
        writeln!(f, "TTL: {}", self.ttl)?;
        writeln!(f, "RDLENGTH: 0x{:x}", self.rdlength)?;
        writeln!(
            f,
            "IP address: {}.{}.{}.{}",
            self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3]
        )?;
        Ok(())
    }
}

/// Stores the response in easy to interpret manner
///
/// A Response is made up of the query given to the server and a bunch of
/// Resource Records (RR). Each RR will include the resource type, class, and
/// name. For the A records we're requesting, we will get an A record, of Internet class,
/// ie an IPv4 address
pub struct Response {
    /// The Query part of the response we obtain from the server
    query: Query,
    /// A collection of resource records all parsed neatly and kept separately
    /// for easy iteration
    rr: Vec<ResourceRecord>,
}

impl FromBytes for Response {
    // Try to construct Response from raw byte data from network
    // We will also try to check if a valid DNS response has been sent back to us
    fn from_bytes(bytes: &[u8]) -> Result<Box<Self>> {
        debug!("Parsing response into struct");
        // Check message length
        let l = bytes.len();
        let messagelen = Response::u8_to_u16(bytes[0], bytes[1]);
        if messagelen == (l - 2) as u16 {
            debug!("Appear to have gotten good message from server");
        } else {
            error!(
                "Expected and observed message length don't match: {} and {} respectively",
                l - 2,
                messagelen
            );
        }
        // Start index at 2 to skip over message length bytes
        let mut index = 2;
        let query = *Query::from_bytes(&bytes[index..])?;
        index += query.len() + 2; // TODO: needs explanation why it works
        let mut rrvec: Vec<ResourceRecord> = Vec::new();
        while index < l {
            match ResourceRecord::from_bytes(&bytes[index..]) {
                Ok(rr) => {
                    index += rr.len();
                    rrvec.push(*rr);
                }
                Err(_) => break,
            }
        }
        Ok(Box::new(Response { query, rr: rrvec }))
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.query.header)?;
        writeln!(
            f,
            "Name: {}",
            String::from_utf8(self.query.qname.to_owned()).unwrap()
        )?;
        writeln!(f, "Res type: 0x{:x}", self.query.qtype)?;
        writeln!(f, "Class: 0x{:x}", self.query.qclass)?;
        for record in self.rr.iter() {
            writeln!(f)?;
            writeln!(f, "{}", record)?;
        }
        Ok(())
    }
}

/// Craft the actual query for a particular domain and returns a Query object
///
/// The query is made for an A record of type Internet, ie, a normal IPv4 address
/// should be returned from the DNS server.
///
/// Convert this Query into bytes to be sent over the network by calling [Query::as_bytes()]
pub fn build_query(domain: &str) -> Result<Query, DomainError> {
    // TODO: generate identification randomly
    let header = Header {
        identification: 0x304e, // chosen by random dice roll, secure
        packed_second_row: 0x0100,
        qdcount: 0x0001,
        ancount: 0x0000,
        nscount: 0x0000,
        arcount: 0x0000,
    };
    let mut qname: Vec<u8> = Vec::new();
    let split_domain: Vec<&str> = domain.split('.').collect();
    for part in split_domain {
        if part.is_empty() {
            return Err(DomainError);
        }
        let l = part.len() as u8;
        if l != 0 {
            qname.push(l);
            qname.extend_from_slice(part.as_bytes());
        }
    }
    qname.push(0x00); // Denote that hostname has ended by pushing 0x00
    debug!("Crafted query successfully!");
    Ok(Query {
        header,
        qname,
        qtype: QTYPE,
        qclass: QCLASS,
    })
}
