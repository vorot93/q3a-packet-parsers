use byteorder::{NetworkEndian, WriteBytesExt};
use hex_literal::hex;
use nom::{
    branch::alt,
    bytes::complete::*,
    combinator::{eof, map, map_opt, map_res, opt, rest},
    multi::many_till,
    number::complete::*,
    sequence::terminated,
    *,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ffi::CString,
    fmt::{self, Display},
    io::Write,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
};

pub fn read_cstring_cons(input: &[u8]) -> IResult<&[u8], CString> {
    map(
        (map_res(take_till(|v| v == 0), CString::new), take(1_usize)),
        |(v, _)| v,
    )
    .parse(input)
}

pub fn read_string_rest(input: &[u8]) -> IResult<&[u8], String> {
    map(rest, |b| String::from_utf8_lossy(b).to_string()).parse(input)
}

const KV_SEPARATOR: u8 = 0x5C;
const KV_SEPARATOR_S: &str = "\\";

fn parse_kv_word(input: &[u8]) -> IResult<&[u8], String> {
    map(
        (
            tag(KV_SEPARATOR_S),
            take_till(|c| c == KV_SEPARATOR || c == b'\n'),
        ),
        |(_, data)| String::from_utf8_lossy(data).into_owned(),
    )
    .parse(input)
}

fn parse_kv_pair(input: &[u8]) -> IResult<&[u8], (String, String)> {
    (parse_kv_word, parse_kv_word).parse(input)
}

fn parse_kv_pairs(input: &[u8]) -> IResult<&[u8], HashMap<String, String>> {
    map(many_till(parse_kv_pair, eof), |pairs| {
        pairs.0.into_iter().collect()
    })
    .parse(input)
}

fn parse_kv_pairs_till_nl(input: &[u8]) -> IResult<&[u8], HashMap<String, String>> {
    map(
        many_till(
            parse_kv_pair,
            alt((map(tag("\n"), |_| ()), map(eof, |_| ()))),
        ),
        |pairs| pairs.0.into_iter().collect(),
    )
    .parse(input)
}

fn write_kv_pairs<K, V>(
    pairs: &mut dyn Iterator<Item = (K, V)>,
    out: &mut dyn Write,
) -> Result<(), anyhow::Error>
where
    K: AsRef<str> + Display + Ord,
    V: AsRef<str> + Display + Ord,
{
    for (k, v) in pairs.collect::<BTreeMap<_, _>>() {
        out.write_all(format!("\\{}", k).as_bytes())?;
        out.write_all(format!("\\{}", v).as_bytes())?;
    }

    Ok(())
}

fn parse_ip_addr(input: &[u8]) -> IResult<&[u8], SocketAddrV4> {
    map(
        (be_u8, be_u8, be_u8, be_u8, be_u16),
        |(a, b, c, d, port)| SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port),
    )
    .parse(input)
}

/// Parses the `\ip:port` records of a `getserversResponse`, returning the
/// addresses and whether the `\EOT` terminator was present.
///
/// A master may split its server list across several UDP datagrams; only the
/// last one ends with `\EOT`. The address loop therefore stops at either the
/// `\EOT` marker (`eot = true`, the final datagram) or the end of the datagram
/// (`eot = false`, more datagrams expected). `many_till` tests the terminator
/// before each record, so the `\EOT` bytes are never mistaken for an address.
fn parse_ip_addrs(input: &[u8]) -> IResult<&[u8], (HashSet<SocketAddrV4>, bool)> {
    map(
        many_till(
            (tag(KV_SEPARATOR_S), parse_ip_addr),
            alt((
                map((tag(KV_SEPARATOR_S), tag("EOT")), |_| true),
                map(eof, |_| false),
            )),
        ),
        |(data, eot)| (data.into_iter().map(|(_, ip)| ip).collect(), eot),
    )
    .parse(input)
}

fn parse_ip6_addr(input: &[u8]) -> IResult<&[u8], SocketAddrV6> {
    map((be_u128, be_u16), |(ip, port)| {
        SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0)
    })
    .parse(input)
}

/// Parses the `\`(IPv4) and `/`(IPv6) records of a `getserversExtResponse`,
/// returning the addresses and whether the `\EOT` terminator was present.
///
/// Handles three terminator forms:
/// - `\EOT` — final datagram (eot = true)
/// - `\` at end of input — Dæmon/Unvanquished trailing separator without EOT
///   (eot = false)
/// - bare end of input — standard intermediate datagram (eot = false)
fn parse_ip_addrs_ext(input: &[u8]) -> IResult<&[u8], (HashSet<SocketAddr>, bool)> {
    map(
        many_till(
            alt((
                map((tag(KV_SEPARATOR_S), parse_ip_addr), |(_, v4)| SocketAddr::V4(v4)),
                map((tag("/"), parse_ip6_addr), |(_, v6)| SocketAddr::V6(v6)),
            )),
            alt((
                map((tag(KV_SEPARATOR_S), tag("EOT")), |_| true),
                // Dæmon/Unvanquished sends a trailing `\` after the last
                // server address rather than `\EOT` for non-final packets.
                map((tag(KV_SEPARATOR_S), eof), |_| false),
                map(eof, |_| false),
            )),
        ),
        |(data, eot)| (data.into_iter().collect(), eot),
    )
    .parse(input)
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChallengeResponseData {
    pub id: String,
}

impl ChallengeResponseData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(read_string_rest, |id| Self { id }).parse(input)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Info {
    pub info: HashMap<String, String>,
}

impl Info {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map((tag("\n"), parse_kv_pairs), |(_, info)| Self { info }).parse(input)
    }

    fn write_bytes(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        write_kv_pairs(&mut self.info.iter(), out)
    }
}

pub type InfoResponseData = Info;
pub type ConnectData = Info;
pub type GetMOTDData = Info;

#[derive(Clone, Debug, PartialEq)]
pub struct RequestData {
    pub challenge: String,
}

impl RequestData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(read_string_rest, |challenge| Self { challenge }).parse(input)
    }

    fn write_bytes(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        out.write_all(format!(" {}", &self.challenge).as_bytes())?;
        Ok(())
    }
}

pub type GetInfoData = RequestData;
pub type GetStatusData = RequestData;

#[derive(Clone, Debug, PartialEq)]
pub struct Player {
    pub score: i32,
    pub ping: u32,
    pub name: String,
    pub team: Option<i32>,
}

impl Player {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        // Take one line (without its newline), consume an optional trailing
        // newline, then parse the line body forgivingly. `map_opt` turns a
        // `None` into a recoverable error at the original position, so the
        // best-effort player loop can skip the line and continue.
        map_opt(
            terminated(take_till(|c| c == b'\n'), opt(tag("\n"))),
            parse_player_line,
        )
        .parse(input)
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self.team {
            Some(team) => {
                format!("{} {} \"{}\" {}\n", self.score, self.ping, self.name, team).into_bytes()
            }
            None => format!("{} {} \"{}\"\n", self.score, self.ping, self.name).into_bytes(),
        }
    }
}

/// Parse the player list best-effort: keep every line that parses as a player,
/// skip every line that doesn't. One malformed line never discards the response.
fn best_effort_players(input: &[u8]) -> IResult<&[u8], Vec<Player>> {
    map(
        many_till(
            alt((map(Player::from_bytes, Some), map(skip_line, |_| None))),
            eof,
        ),
        |(items, _)| items.into_iter().flatten().collect(),
    )
    .parse(input)
}

/// Consume one line up to and including its newline (or to end of input).
/// Always consumes ≥1 byte on non-empty input, guaranteeing loop progress.
fn skip_line(input: &[u8]) -> IResult<&[u8], ()> {
    map((take_till(|c| c == b'\n'), opt(tag("\n"))), |_| ()).parse(input)
}

/// Parse one player line body (no trailing newline): `<score> <ping> "<name>"[ <team>]`.
/// The name spans the first to the last double-quote on the line, so embedded
/// quotes survive. Returns `None` when the line is not a well-formed player record.
fn parse_player_line(line: &[u8]) -> Option<Player> {
    let s = String::from_utf8_lossy(line);
    let first_q = s.find('"')?;
    let last_q = s.rfind('"')?;
    if last_q <= first_q {
        return None; // need two distinct quotes
    }
    let name = s[first_q + 1..last_q].to_string();

    // score and ping: the first two whitespace-separated tokens before the name.
    let mut head = s[..first_q].split_whitespace();
    let score: i32 = head.next()?.parse().ok()?;
    let ping: u32 = head.next()?.parse().ok()?;

    // optional trailing team integer after the closing quote (qfusion).
    let tail = s[last_q + 1..].trim();
    let team = if tail.is_empty() {
        None
    } else {
        tail.parse::<i32>().ok()
    };

    Some(Player { score, ping, name, team })
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StatusResponseData {
    pub info: HashMap<String, String>,
    pub players: Vec<Player>,
}

impl StatusResponseData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(
            (tag("\n"), parse_kv_pairs_till_nl, best_effort_players),
            |(_, info, players)| Self { info, players },
        )
        .parse(input)
    }

    fn write_bytes(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        out.write_all(b"\n")?;
        Info {
            info: self.info.clone(),
        }
        .write_bytes(out)?;
        out.write_all(b"\n")?;

        for player in &self.players {
            out.write_all(&player.to_bytes())?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MasterQueryExtra {
    Empty,
    Full,
    Ipv4,
    Ipv6,
}

impl Display for MasterQueryExtra {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use MasterQueryExtra::*;
        write!(
            fmt,
            "{}",
            match self {
                Empty => "empty",
                Full => "full",
                Ipv4 => "ipv4",
                Ipv6 => "ipv6",
            }
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetServersData {
    pub request_tag: Option<String>,
    pub version: u32,
    pub extra: HashSet<MasterQueryExtra>,
}

impl GetServersData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(
            (
                tag(" "),
                map_res(take_until(" "), |b: &[u8]| {
                    u32::from_str(&String::from_utf8_lossy(b))
                }),
                map(opt(tag(" empty")), |v| v.is_some()),
                map(opt(tag(" full")), |v| v.is_some()),
            ),
            |(_, version, empty, full)| Self {
                version,
                request_tag: None,
                extra: {
                    let mut out = HashSet::new();
                    for &(flag, v) in &[
                        (empty, MasterQueryExtra::Empty),
                        (full, MasterQueryExtra::Full),
                    ] {
                        if flag {
                            out.insert(v);
                        }
                    }
                    out
                },
            },
        )
        .parse(input)
    }

    fn write_bytes(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        if let Some(request_tag) = &self.request_tag {
            out.write_all(&format!(" {}", request_tag).into_bytes())?;
        }
        out.write_all(&format!(" {}", self.version).into_bytes())?;
        for extra in &self.extra {
            out.write_all(&format!(" {}", extra).into_bytes())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetServersResponseData {
    pub data: HashSet<SocketAddrV4>,
    /// Whether this datagram carried the `\EOT` terminator, i.e. it is the final
    /// packet of the master's (possibly multi-datagram) response. `false` means
    /// more datagrams are expected.
    pub eot: bool,
}

impl GetServersResponseData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(parse_ip_addrs, |(data, eot)| Self { data, eot }).parse(input)
    }

    fn write_bytes(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        for server in &self.data {
            out.write_all(&[KV_SEPARATOR])?;
            out.write_all(&server.ip().octets())?;
            out.write_u16::<NetworkEndian>(server.port())?
        }

        if self.eot {
            out.write_all(&[KV_SEPARATOR])?;
            out.write_all(b"EOT")?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetServersExtData {
    pub request_tag: String,
    pub version: u32,
    pub extra: HashSet<MasterQueryExtra>,
}

impl GetServersExtData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(
            (
                tag(" "),
                map(take_until(" "), |b: &[u8]| String::from_utf8_lossy(b).into_owned()),
                tag(" "),
                map_res(take_till(|c: u8| c == b' '), |b: &[u8]| u32::from_str(&String::from_utf8_lossy(b))),
                map(opt(tag(" empty")), |v| v.is_some()),
                map(opt(tag(" full")), |v| v.is_some()),
                map(opt(tag(" ipv4")), |v| v.is_some()),
                map(opt(tag(" ipv6")), |v| v.is_some()),
            ),
            |(_, request_tag, _, version, empty, full, ipv4, ipv6)| Self {
                request_tag,
                version,
                extra: {
                    let mut out = HashSet::new();
                    for &(flag, v) in &[
                        (empty, MasterQueryExtra::Empty),
                        (full, MasterQueryExtra::Full),
                        (ipv4, MasterQueryExtra::Ipv4),
                        (ipv6, MasterQueryExtra::Ipv6),
                    ] {
                        if flag {
                            out.insert(v);
                        }
                    }
                    out
                },
            },
        )
        .parse(input)
    }

    fn write_bytes(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        out.write_all(format!(" {}", self.request_tag).as_bytes())?;
        out.write_all(format!(" {}", self.version).as_bytes())?;
        for extra in &self.extra {
            out.write_all(format!(" {}", extra).as_bytes())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GetServersExtResponseData {
    pub data: HashSet<SocketAddr>,
    pub eot: bool,
}

/// Skip the optional Dæmon/Unvanquished label header that precedes server
/// addresses in some `getserversExtResponse` packets:
/// `\0<index>\0<numpackets>\0<label>` where each field is a null-terminated
/// ASCII string.  Standard DarkPlaces responses omit this prefix entirely.
fn skip_ext_label_header(input: &[u8]) -> IResult<&[u8], ()> {
    // If the input starts with a null byte (which can never be the start of a
    // server-address record or EOT marker) we treat it as a label header.
    map(
        opt((
            tag(&[0u8][..]),              // null before index
            take_till(|b| b == 0u8),      // index digits
            tag(&[0u8][..]),              // null before numpackets
            take_till(|b| b == 0u8),      // numpackets digits
            tag(&[0u8][..]),              // null before label
            take_till(|b| b == KV_SEPARATOR), // label text (stops at \)
        )),
        |_| (),
    )
    .parse(input)
}

impl GetServersExtResponseData {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        map(
            (skip_ext_label_header, parse_ip_addrs_ext),
            |(_, (data, eot))| Self { data, eot },
        )
        .parse(input)
    }

    fn write_bytes(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        for server in &self.data {
            match server {
                SocketAddr::V4(v4) => {
                    out.write_all(&[KV_SEPARATOR])?;
                    out.write_all(&v4.ip().octets())?;
                    out.write_u16::<NetworkEndian>(v4.port())?;
                }
                SocketAddr::V6(v6) => {
                    out.write_all(b"/")?;
                    out.write_all(&v6.ip().octets())?;
                    out.write_u16::<NetworkEndian>(v6.port())?;
                }
            }
        }
        if self.eot {
            out.write_all(&[KV_SEPARATOR])?;
            out.write_all(b"EOT")?;
        }
        Ok(())
    }
}


#[derive(Clone, Debug, PartialEq)]
pub enum Packet {
    ChallengeRequest,
    ChallengeResponse(ChallengeResponseData),
    Connect(ConnectData),
    ConnectResponse,
    GetInfo(GetInfoData),
    GetMOTD(GetMOTDData),
    GetServers(GetServersData),
    GetServersResponse(GetServersResponseData),
    GetServersExt(GetServersExtData),
    GetServersExtResponse(GetServersExtResponseData),
    GetStatus(GetStatusData),
    InfoResponse(InfoResponseData),
    StatusResponse(StatusResponseData),
}

#[derive(Clone, Copy, Debug)]
pub enum PacketType {
    ChallengeRequest,
    ChallengeResponse,
    Connect,
    ConnectResponse,
    GetInfo,
    GetMOTD,
    GetServers,
    GetServersResponse,
    GetServersExt,
    GetServersExtResponse,
    GetStatus,
    InfoResponse,
    StatusResponse,
}

impl Packet {
    pub fn get_type(&self) -> PacketType {
        use Packet::*;

        match *self {
            ChallengeRequest => PacketType::ChallengeRequest,
            ChallengeResponse(_) => PacketType::ChallengeResponse,
            Connect(_) => PacketType::Connect,
            ConnectResponse => PacketType::ConnectResponse,
            GetInfo(_) => PacketType::GetInfo,
            GetMOTD(_) => PacketType::GetMOTD,
            GetServers(_) => PacketType::GetServers,
            GetServersResponse(_) => PacketType::GetServersResponse,
            GetServersExt(_) => PacketType::GetServersExt,
            GetServersExtResponse(_) => PacketType::GetServersExtResponse,
            GetStatus(_) => PacketType::GetStatus,
            InfoResponse(_) => PacketType::InfoResponse,
            StatusResponse(_) => PacketType::StatusResponse,
        }
    }

    pub fn from_bytes(input: &[u8]) -> IResult<&[u8], Packet> {
        let (input, (_, packet_type)) = (
            tag(&hex!("ffffffff")[..]),
            alt((
                tag("connect"),
                tag("getinfo"),
                tag("getmotd"),
                tag("getstatus"),
                tag("getserversExtResponse"),
                tag("getserversResponse"),
                tag("getserversExt"),
                tag("getservers"),
                tag("getchallenge"),
                tag("infoResponse"),
                tag("statusResponse"),
                tag("connectResponse"),
                tag("challengeResponse"),
            )),
        )
            .parse(input)?;

        match packet_type {
            b"getchallenge" => Ok((input, Packet::ChallengeRequest)),
            b"challengeResponse" => {
                map(ChallengeResponseData::from_bytes, Packet::ChallengeResponse).parse(input)
            }
            b"connect" => map(ConnectData::from_bytes, Packet::Connect).parse(input),
            b"connectResponse" => Ok((input, Packet::ConnectResponse)),
            b"getinfo" => map(GetInfoData::from_bytes, Packet::GetInfo).parse(input),
            b"getmotd" => map(GetMOTDData::from_bytes, Packet::GetMOTD).parse(input),
            b"getservers" => map(GetServersData::from_bytes, Packet::GetServers).parse(input),
            b"getserversResponse" => map(
                GetServersResponseData::from_bytes,
                Packet::GetServersResponse,
            )
            .parse(input),
            b"getserversExt" => {
                map(GetServersExtData::from_bytes, Packet::GetServersExt).parse(input)
            }
            b"getserversExtResponse" => map(
                GetServersExtResponseData::from_bytes,
                Packet::GetServersExtResponse,
            )
            .parse(input),
            b"getstatus" => map(GetStatusData::from_bytes, Packet::GetStatus).parse(input),
            b"infoResponse" => map(InfoResponseData::from_bytes, Packet::InfoResponse).parse(input),
            b"statusResponse" => {
                map(StatusResponseData::from_bytes, Packet::StatusResponse).parse(input)
            }
            _ => unreachable!(),
        }
    }

    pub fn write_bytes(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        use Packet::*;

        out.write_all(&[255, 255, 255, 255])?;
        match self {
            GetServers(data) => {
                out.write_all(b"getservers")?;
                data.write_bytes(out)?;
            }
            GetServersResponse(data) => {
                out.write_all(b"getserversResponse")?;
                data.write_bytes(out)?;
            }
            GetInfo(data) => {
                out.write_all(b"getinfo")?;
                data.write_bytes(out)?;
            }
            GetStatus(data) => {
                out.write_all(b"getstatus")?;
                data.write_bytes(out)?;
            }
            StatusResponse(data) => {
                out.write_all(b"statusResponse")?;
                data.write_bytes(out)?;
            }
            GetServersExt(data) => {
                out.write_all(b"getserversExt")?;
                data.write_bytes(out)?;
            }
            GetServersExtResponse(data) => {
                out.write_all(b"getserversExtResponse")?;
                data.write_bytes(out)?;
            }
            _ => unimplemented!(),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use maplit::hashset;

    fn kv_pair_fixtures() -> (String, HashMap<String, String>) {
        let b = "\\g_needpass\\0\\gametype\\0\\pure\\1\\sv_maxclients\\8\\voip\\opus".to_string();
        let v = [
            ("g_needpass", "0"),
            ("pure", "1"),
            ("gametype", "0"),
            ("sv_maxclients", "8"),
            ("voip", "opus"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<HashMap<String, String>>();

        (b, v)
    }

    #[test]
    fn test_parse_kv_pairs() {
        let (fixture, expectation) = kv_pair_fixtures();

        let result = parse_kv_pairs(fixture.as_bytes()).unwrap().1;

        assert_eq!(expectation, result);
    }

    #[test]
    fn test_write_kv_pairs() {
        let (expectation, fixture) = kv_pair_fixtures();

        let mut result = Vec::new();
        write_kv_pairs(&mut fixture.into_iter(), &mut result).unwrap();

        assert_eq!(expectation.into_bytes(), result);
    }

    fn player_fixtures<'a>() -> (&'a [u8], Player) {
        let b = "9000 30 \"Grunt\"\n".as_bytes();
        let p = Player {
            score: 9000,
            ping: 30,
            name: "Grunt".to_string(),
            team: None,
        };
        (b, p)
    }

    #[test]
    fn parse_player_string() {
        let (fixture, expectation) = player_fixtures();

        let result = Player::from_bytes(fixture).unwrap().1;

        assert_eq!(expectation, result);
    }

    #[test]
    fn write_player_string() {
        let (expectation, fixture) = player_fixtures();

        let result = Player::to_bytes(&fixture);

        assert_eq!(expectation.to_vec(), result);
    }

    fn pkt_fixtures() -> Vec<(Vec<u8>, Packet)> {
        vec![
            (
                b"\xff\xff\xff\xffinfoResponse\n\\game\\cpma\\voip\\opus\\g_needpass\\0\\pure\\0\\gametype\\9\\sv_maxclients\\16\\g_humanplayers\\0\\clients\\0\\mapname\\cpm16\\hostname\\v2c - CPMA 1.48/CPM FFA/1V1/2V2/TDM/CTF/CTFS/NTF/HM - #1\\protocol\\68\\gamename\\Quake3Arena".to_vec(),
                Packet::InfoResponse(InfoResponseData {
                    info: [
                        ("game", "cpma"),
                        ("voip", "opus"),
                        ("g_needpass", "0"),
                        ("pure", "0"),
                        ("gametype", "9"),
                        ("sv_maxclients", "16"),
                        ("g_humanplayers", "0"),
                        ("clients", "0"),
                        ("mapname", "cpm16"),
                        (
                            "hostname",
                            "v2c - CPMA 1.48/CPM FFA/1V1/2V2/TDM/CTF/CTFS/NTF/HM - #1",
                        ),
                        ("protocol", "68"),
                        ("gamename", "Quake3Arena"),
                    ]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<_>(),
                }),
            ),
            (
                b"\xff\xff\xff\xffgetservers 68 empty full".to_vec(),
                Packet::GetServers(GetServersData {
                    request_tag: None,
                    version: 68,
                    extra: hashset! {
                        MasterQueryExtra::Empty,
                        MasterQueryExtra::Full,
                    },
                }),
            ),
            (
                b"\xff\xff\xff\xffgetserversResponse\\\xb2\x3e\xca\xdb\x6d\x38\\\xbc\x28\x47\xd5\x6d\x42\\\x18\xa6\xfc\xd1\x6d\x3e\\EOT".to_vec(),
                Packet::GetServersResponse(GetServersResponseData {
                    data: vec![
                        "178.62.202.219:27960",
                        "188.40.71.213:27970",
                        "24.166.252.209:27966",
                    ]
                    .into_iter()
                    .map(|v| SocketAddrV4::from_str(v).unwrap())
                    .collect(),
                    eot: true,
                }),
            ),
            (
                b"\xff\xff\xff\xffstatusResponse\n\\challenge\\RGS\\dmflags\\8\\fraglimit\\20\\timelimit\\15\\sv_privateClients\\0\\sv_hostname\\games.on.net #5 Q3A (NSW)\\sv_maxclients\\16\\sv_punkbuster\\0\\sv_maxRate\\0\\sv_minPing\\0\\sv_maxPing\\500\\sv_floodProtect\\0\\sv_allowDownload\\1\\bot_minplayers\\2\\g_needpass\\0\\capturelimit\\8\\g_maxGameClients\\0\\g_gametype\\0\\version\\Q3 1.32c win-x86 May  8 2006\\protocol\\68\\mapname\\q3dm8\\.Administrator\\Wishful Thinking!\\.Website\\www.games.on.net\\.Location\\Sydney, Australia\\.TeamSpeak3\\ts3.wishfulthinkings.net\\sv_dlURL\\http://cdn.wishfulthinkings.net\\gamename\\baseq3\n8 0 \"Xaero\"\n-8 10 \"Sarge\"\n".to_vec(),
                Packet::StatusResponse(StatusResponseData {
                    info: [
                        ("g_needpass", "0"),
                        (".Administrator", "Wishful Thinking!"),
                        ("sv_punkbuster", "0"),
                        ("sv_maxPing", "500"),
                        ("sv_privateClients", "0"),
                        ("sv_hostname", "games.on.net #5 Q3A (NSW)"),
                        ("version", "Q3 1.32c win-x86 May  8 2006"),
                        ("sv_dlURL", "http://cdn.wishfulthinkings.net"),
                        ("g_maxGameClients", "0"),
                        ("fraglimit", "20"),
                        ("capturelimit", "8"),
                        ("mapname", "q3dm8"),
                        ("dmflags", "8"),
                        ("sv_allowDownload", "1"),
                        ("timelimit", "15"),
                        ("sv_maxRate", "0"),
                        (".TeamSpeak3", "ts3.wishfulthinkings.net"),
                        ("sv_floodProtect", "0"),
                        ("sv_maxclients", "16"),
                        (".Location", "Sydney, Australia"),
                        ("protocol", "68"),
                        ("sv_minPing", "0"),
                        ("g_gametype", "0"),
                        (".Website", "www.games.on.net"),
                        ("challenge", "RGS"),
                        ("bot_minplayers", "2"),
                        ("gamename", "baseq3"),
                    ]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<_>(),
                    players: vec![
                        Player {
                            name: "Xaero".to_string(),
                            ping: 0,
                            score: 8,
                            team: None,
                        },
                        Player {
                            name: "Sarge".to_string(),
                            ping: 10,
                            score: -8,
                            team: None,
                        },
                    ],
                }),
            ),
        ]
    }

    #[test]
    fn parse() {
        for (input, expectation) in &pkt_fixtures() {
            let result = Packet::from_bytes(input).unwrap().1;

            assert_eq!(*expectation, result);
        }
    }

    #[test]
    fn getservers_response_without_eot_parses_as_partial() {
        // A non-terminating master datagram (no trailing \EOT) must still parse,
        // yielding the addresses it carries. Real masters split large lists over
        // several datagrams; only the last one ends with \EOT.
        let mut input = b"\xff\xff\xff\xffgetserversResponse".to_vec();
        input.extend_from_slice(b"\\\x0a\x00\x00\x01\x6d\x38"); // 10.0.0.1:27960
        input.extend_from_slice(b"\\\x0a\x00\x00\x02\x6d\x39"); // 10.0.0.2:27961

        let (_, pkt) = Packet::from_bytes(&input).unwrap();
        match pkt {
            Packet::GetServersResponse(d) => {
                let expected: HashSet<SocketAddrV4> = ["10.0.0.1:27960", "10.0.0.2:27961"]
                    .into_iter()
                    .map(|s| SocketAddrV4::from_str(s).unwrap())
                    .collect();
                assert_eq!(d.data, expected);
                assert!(!d.eot, "a datagram without \\EOT must report eot = false");
            }
            other => panic!("expected GetServersResponse, got {other:?}"),
        }
    }

    #[test]
    fn getservers_response_with_eot_roundtrips_and_sets_eot() {
        // Writing a terminating response now emits \EOT; parsing it back must
        // recover both the addresses and eot = true.
        let data: HashSet<SocketAddrV4> = ["10.0.0.1:27960"]
            .into_iter()
            .map(|s| SocketAddrV4::from_str(s).unwrap())
            .collect();
        let pkt = Packet::GetServersResponse(GetServersResponseData {
            data: data.clone(),
            eot: true,
        });

        let mut bytes = Vec::new();
        pkt.write_bytes(&mut bytes).unwrap();
        assert!(
            bytes.ends_with(b"\\EOT"),
            "terminating packet must end with \\EOT"
        );

        let (_, parsed) = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn write() {}

    #[test]
    fn player_name_with_embedded_quote_parses() {
        // Name contains a literal double-quote: it must span first..last quote.
        let bytes = b"7 12 \"He said \"hi\"\"\n";
        let p = Player::from_bytes(bytes).unwrap().1;
        assert_eq!(p.score, 7);
        assert_eq!(p.ping, 12);
        assert_eq!(p.name, "He said \"hi\"");
        assert_eq!(p.team, None);
    }

    #[test]
    fn player_line_without_trailing_newline_parses() {
        let bytes = b"3 45 \"Lonely\""; // no trailing \n
        let p = Player::from_bytes(bytes).unwrap().1;
        assert_eq!(p.score, 3);
        assert_eq!(p.ping, 45);
        assert_eq!(p.name, "Lonely");
    }

    #[test]
    fn player_line_tolerates_extra_spaces() {
        let bytes = b"10   20   \"Spaced\"\n";
        let p = Player::from_bytes(bytes).unwrap().1;
        assert_eq!(p.score, 10);
        assert_eq!(p.ping, 20);
        assert_eq!(p.name, "Spaced");
    }

    #[test]
    fn qfusion_player_with_team_parses_and_roundtrips() {
        // qfusion (Warsow/Warfork): trailing team field after the name.
        let bytes = "-5 0 \"SisterClaw^7(1)\" 3\n".as_bytes();
        let p = Player::from_bytes(bytes).unwrap().1;
        assert_eq!(p.score, -5);
        assert_eq!(p.ping, 0);
        assert_eq!(p.name, "SisterClaw^7(1)");
        assert_eq!(p.team, Some(3));
        assert_eq!(p.to_bytes(), bytes.to_vec()); // round-trips with the team
    }

    #[test]
    fn quake3_player_has_no_team() {
        let bytes = "9000 30 \"Grunt\"\n".as_bytes();
        let p = Player::from_bytes(bytes).unwrap().1;
        assert_eq!(p.team, None);
        assert_eq!(p.to_bytes(), bytes.to_vec()); // no team -> unchanged format
    }

    #[test]
    fn status_response_with_team_players_parses() {
        // The previously-failing qfusion shape: players carry a trailing team.
        let body = b"\xff\xff\xff\xffstatusResponse\n\\sv_hostname\\Test\\protocol\\22\n2 0 \"Cathy\" 1\n14 0 \"Silver\" 1\n-9999 0 \"Lobita\" 0\n";
        match Packet::from_bytes(body).unwrap().1 {
            Packet::StatusResponse(d) => {
                assert_eq!(d.players.len(), 3);
                assert_eq!(d.players[0].name, "Cathy");
                assert_eq!(d.players[0].team, Some(1));
                assert_eq!(d.players[2].team, Some(0));
            }
            other => panic!("expected StatusResponse, got {:?}", other.get_type()),
        }
    }

    #[test]
    fn getservers_ext_request_writes_gamename_version_flags() {
        let mut bytes = Vec::new();
        Packet::GetServersExt(GetServersExtData {
            request_tag: "Unvanquished".to_string(),
            version: 86,
            extra: hashset! { MasterQueryExtra::Empty, MasterQueryExtra::Full, MasterQueryExtra::Ipv4 },
        })
        .write_bytes(&mut bytes)
        .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("getserversExt"), "{text:?}");
        assert!(text.contains("Unvanquished"), "{text:?}");
        assert!(text.contains("86"), "{text:?}");
        for flag in ["empty", "full", "ipv4"] {
            assert!(text.contains(flag), "missing {flag} in {text:?}");
        }
        // gamename + version round-trip. NOT full equality: `extra` is a HashSet,
        // so write order is nondeterministic while `from_bytes` parses flags
        // positionally — asserting the flag set through the round-trip is flaky.
        match Packet::from_bytes(&bytes).unwrap().1 {
            Packet::GetServersExt(d) => {
                assert_eq!(d.request_tag, "Unvanquished");
                assert_eq!(d.version, 86);
            }
            other => panic!("expected GetServersExt, got {:?}", other.get_type()),
        }
    }

    #[test]
    fn getservers_ext_request_parses_without_flags() {
        let mut bytes = Vec::new();
        Packet::GetServersExt(GetServersExtData {
            request_tag: "Unvanquished".to_string(),
            version: 86,
            extra: HashSet::new(),
        })
        .write_bytes(&mut bytes)
        .unwrap();
        match Packet::from_bytes(&bytes).unwrap().1 {
            Packet::GetServersExt(d) => {
                assert_eq!(d.request_tag, "Unvanquished");
                assert_eq!(d.version, 86);
                assert!(d.extra.is_empty());
            }
            other => panic!("expected GetServersExt, got {:?}", other.get_type()),
        }
    }

    #[test]
    fn getservers_ext_response_parses_v4_and_v6() {
        use std::net::{Ipv6Addr, SocketAddrV6};
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 27960));
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 27961, 0, 0));
        let pkt = Packet::GetServersExtResponse(GetServersExtResponseData {
            data: hashset! { v4, v6 },
            eot: true,
        });
        let mut bytes = Vec::new();
        pkt.write_bytes(&mut bytes).unwrap();
        // dispatched as Ext, not plain getserversResponse:
        match Packet::from_bytes(&bytes).unwrap().1 {
            Packet::GetServersExtResponse(d) => {
                assert!(d.eot);
                assert!(d.data.contains(&v4));
                assert!(d.data.contains(&v6));
            }
            other => panic!("expected GetServersExtResponse, got {:?}", other.get_type()),
        }
    }

    #[test]
    fn status_response_keeps_good_players_and_skips_garbage() {
        // A malformed line between two good ones must not discard the server or
        // the well-formed players around it.
        let body = b"\xff\xff\xff\xffstatusResponse\n\\sv_hostname\\Test\\protocol\\68\n8 0 \"Xaero\"\nGARBAGE LINE\n-8 10 \"Sarge\"\n";
        match Packet::from_bytes(body).unwrap().1 {
            Packet::StatusResponse(d) => {
                assert_eq!(d.players.len(), 2, "garbage line should be skipped, not fatal");
                assert_eq!(d.players[0].name, "Xaero");
                assert_eq!(d.players[1].name, "Sarge");
            }
            other => panic!("expected StatusResponse, got {:?}", other.get_type()),
        }
    }

    #[test]
    fn info_block_without_trailing_newline_still_parses() {
        // Some servers end the info block at end-of-datagram with no player section
        // and no terminating "\n". The server (and its rules) must still parse.
        let body = b"\xff\xff\xff\xffstatusResponse\n\\sv_hostname\\NoNL\\protocol\\68";
        match Packet::from_bytes(body).unwrap().1 {
            Packet::StatusResponse(d) => {
                assert_eq!(d.info.get("sv_hostname").map(String::as_str), Some("NoNL"));
                assert!(d.players.is_empty());
            }
            other => panic!("expected StatusResponse, got {:?}", other.get_type()),
        }
    }

    #[test]
    fn junk_datagram_is_still_an_error() {
        // Non-statusResponse noise must NOT be coerced into a server.
        let junk = b"\xff\xff\xff\xffwat is this";
        assert!(Packet::from_bytes(junk).is_err());
    }

    #[test]
    fn status_response_with_all_garbage_players_yields_empty_list() {
        // An entirely unparseable player section must still yield the server
        // (with its rules) and an empty player list, not an error.
        let body = b"\xff\xff\xff\xffstatusResponse\n\\sv_hostname\\Test\\protocol\\68\nGARBAGE\nMORE GARBAGE\n";
        match Packet::from_bytes(body).unwrap().1 {
            Packet::StatusResponse(d) => {
                assert_eq!(d.info.get("sv_hostname").map(String::as_str), Some("Test"));
                assert!(
                    d.players.is_empty(),
                    "all-garbage player section should yield no players, not an error",
                );
            }
            other => panic!("expected StatusResponse, got {:?}", other.get_type()),
        }
    }

    #[test]
    fn status_response_final_player_line_without_newline_parses() {
        // The last player line lacks a trailing "\n" (an EOF-terminated datagram).
        // It must still parse, not be dropped.
        let body = b"\xff\xff\xff\xffstatusResponse\n\\sv_hostname\\Test\\protocol\\68\n8 0 \"Xaero\"\n5 12 \"Sarge\"";
        match Packet::from_bytes(body).unwrap().1 {
            Packet::StatusResponse(d) => {
                assert_eq!(d.players.len(), 2, "final line without newline must still parse");
                assert_eq!(d.players[1].name, "Sarge");
                assert_eq!(d.players[1].team, None);
            }
            other => panic!("expected StatusResponse, got {:?}", other.get_type()),
        }
    }

    /// The Unvanquished master sends `getserversExtResponse` with an unusual
    /// `\0index\0numpackets\0label` prefix before the server list.  Verify
    /// that the parser skips the label header and still extracts the servers.
    #[test]
    fn getservers_ext_response_with_daemon_label_header_parses() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        // Bytes representative of the Dæmon getserversExtResponse format:
        // \xff\xff\xff\xff + "getserversExtResponse" + \0 + "1" + \0 + "3" + \0
        // + "[featured]" + \\ + IP + port + \\
        let mut pkt = b"\xff\xff\xff\xffgetserversExtResponse".to_vec();
        pkt.push(0);    // null before index
        pkt.push(b'1'); // index
        pkt.push(0);    // null before numpackets
        pkt.push(b'3'); // numpackets
        pkt.push(0);    // null before label
        pkt.extend_from_slice(b"[featured]");
        pkt.push(0x5c); // KV_SEPARATOR
        pkt.extend_from_slice(&[206, 189, 56, 213]);
        pkt.extend_from_slice(&[0x6d, 0x38]); // port 27960
        pkt.push(0x5c); // trailing backslash

        match Packet::from_bytes(&pkt) {
            Ok((_, Packet::GetServersExtResponse(data))) => {
                let expected = hashset![SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(206, 189, 56, 213), 27960
                ))];
                assert_eq!(data.data, expected, "server address should be parsed");
            }
            Ok((_, other)) => panic!("unexpected packet type: {:?}", other.get_type()),
            Err(e) => panic!("parse failed: {:?}", e),
        }
    }
}
