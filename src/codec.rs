//! protobuf / JCE 通用逆向解析（移植自 `../WeQ` `packages/codec/src/raw`）。
//!
//! 输出统一为 `{tag: value}` 的树，类型信息保留在内部，渲染时可切换展示。
//! JCE 规则严格对齐 QQ 真实包（QQHook TarsParser / TarsInputStream）：
//!   - 头字节：低 4 位 = type，高 4 位 = tag；tag == 15 时再读 1 字节为完整 tag。
//!   - 类型：0 BYTE, 1 SHORT, 2 INT, 3 LONG, 4 FLOAT, 5 DOUBLE,
//!     6 STRING1, 7 STRING4, 8 MAP, 9 LIST, 10 STRUCT_BEGIN,
//!     11 STRUCT_END, 12 ZERO_TAG, 13 SIMPLE_LIST。
//!   - 容器 size 用带头字段（tag=0）编码；非法时兜底无头紧凑长度。

use std::fmt::Write as _;

/// 嵌套解码最大深度。
pub const RV_MAX_DEPTH: usize = 16;
const MAX_CONTAINER_SIZE: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Protobuf,
    Jce,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RvValue {
    /// 整数：protobuf varint（bits=0）或 JCE 定宽整数。`raw` 为无符号原值。
    Int { raw: u64, bits: u8, signed: bool },
    /// 浮点：JCE float/double。
    Float(f64),
    /// protobuf wire 1/5 定长块。
    Fixed { bytes: Vec<u8>, bits: u8 },
    /// 文本：JCE STRING1/STRING4。
    Str { text: String, bytes: Vec<u8> },
    /// 原始字节：protobuf LEN / JCE SIMPLE_LIST。可含自动下钻的嵌套树。
    Bytes {
        bytes: Vec<u8>,
        nested: Option<Vec<RvNode>>,
        nested_kind: Option<Kind>,
    },
    /// 嵌套对象：protobuf 嵌套消息 / JCE STRUCT。
    Obj(Vec<RvNode>),
    /// JCE LIST。
    List(Vec<RvNode>),
    /// JCE MAP。
    Map(Vec<(RvValue, RvNode)>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct RvNode {
    pub tag: u32,
    pub value: RvValue,
}

#[derive(Debug)]
pub struct DecodeError(&'static str);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for DecodeError {}

macro_rules! err {
    ($m:literal) => {
        DecodeError($m)
    };
}

// ─────────────────────────── 通用工具 ───────────────────────────

/// 严格 UTF-8 解码；含非法序列或 C0 控制符（除 \t\n\r）返回 None。
pub fn try_utf8(b: &[u8]) -> Option<String> {
    if b.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(b).ok()?;
    for c in s.chars() {
        let c = c as u32;
        if c < 0x20 && c != 0x09 && c != 0x0a && c != 0x0d {
            return None;
        }
    }
    Some(s.to_string())
}

fn decode_utf8_lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// 定宽无符号值 → 有符号（Java 语义）。
pub fn two_complement(raw: u64, bits: u8) -> i64 {
    if bits == 0 || bits >= 64 {
        return raw as i64;
    }
    let sign = 1u64 << (bits - 1);
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let m = raw & mask;
    if m >= sign {
        (m as i128 - (1i128 << bits)) as i64
    } else {
        m as i64
    }
}

/// int 节点默认展示值。
pub fn rv_int_display(raw: u64, bits: u8, signed: bool) -> i64 {
    if signed && bits > 0 {
        two_complement(raw, bits)
    } else {
        raw as i64
    }
}

/// zigzag 解码（保留给未来的 sint 语义切换展示）。
#[allow(dead_code)]
pub fn zigzag_decode(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

const SEC_2000: u64 = 946_684_800;
const SEC_2100: u64 = 4_102_444_800;

/// 数值是否落在常见时间戳区间（秒或毫秒）。
pub fn timestamp_range(raw: u64) -> Option<(&'static str, u64)> {
    if (SEC_2000 * 1000..SEC_2100 * 1000).contains(&raw) {
        Some(("ms", raw))
    } else if (SEC_2000..SEC_2100).contains(&raw) {
        Some(("sec", raw * 1000))
    } else {
        None
    }
}

// ─────────────────────────── protobuf ───────────────────────────

struct WireField<'a> {
    tag: u32,
    wire: u8,
    payload: &'a [u8],
}

fn read_varint(buf: &[u8], off: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut i = 0usize;
    while i < 10 {
        let b = *buf.get(off + i)?;
        value |= ((b & 0x7f) as u64) << (7 * i);
        i += 1;
        if b & 0x80 == 0 {
            return Some((value, i));
        }
    }
    None
}

fn read_field(buf: &[u8], off: usize) -> Option<WireField<'_>> {
    if off >= buf.len() {
        return None;
    }
    let (key, ks) = read_varint(buf, off)?;
    let wire = (key & 7) as u8;
    let tag = (key >> 3) as u32;
    if tag == 0 {
        return None;
    }
    let cursor = off + ks;
    match wire {
        0 => {
            let (_, n) = read_varint(buf, cursor)?;
            Some(WireField {
                tag,
                wire,
                payload: &buf[cursor..cursor + n],
            })
        }
        1 => {
            if cursor + 8 > buf.len() {
                return None;
            }
            Some(WireField {
                tag,
                wire,
                payload: &buf[cursor..cursor + 8],
            })
        }
        2 => {
            let (len, ls) = read_varint(buf, cursor)?;
            let len = len as usize;
            let start = cursor + ls;
            if start + len > buf.len() {
                return None;
            }
            Some(WireField {
                tag,
                wire,
                payload: &buf[start..start + len],
            })
        }
        5 => {
            if cursor + 4 > buf.len() {
                return None;
            }
            Some(WireField {
                tag,
                wire,
                payload: &buf[cursor..cursor + 4],
            })
        }
        _ => None,
    }
}

/// 递归解码 protobuf 消息（全部字节被完整消费才算成功）。
pub fn decode_protobuf(buf: &[u8], depth: usize) -> Result<Vec<RvNode>, DecodeError> {
    let mut nodes = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        let wf = read_field(buf, off).ok_or(err!("protobuf: 字段解析失败"))?;
        let consumed = field_len(buf, off).ok_or(err!("protobuf: 字段长度"))?;
        let value = match wf.wire {
            0 => {
                let (v, _) = read_varint(wf.payload, 0).ok_or(err!("protobuf: varint"))?;
                RvValue::Int {
                    raw: v,
                    bits: 0,
                    signed: false,
                }
            }
            1 => RvValue::Fixed {
                bytes: wf.payload.to_vec(),
                bits: 64,
            },
            2 => {
                let payload = wf.payload.to_vec();
                let mut value = RvValue::Bytes {
                    bytes: payload.clone(),
                    nested: None,
                    nested_kind: None,
                };
                if let Some((nested, kind)) = nested_bytes(&payload, depth) {
                    value = RvValue::Bytes {
                        bytes: payload,
                        nested: Some(nested),
                        nested_kind: Some(kind),
                    };
                }
                value
            }
            5 => RvValue::Fixed {
                bytes: wf.payload.to_vec(),
                bits: 32,
            },
            _ => return Err(err!("protobuf: 不支持的 wire type")),
        };
        nodes.push(RvNode { tag: wf.tag, value });
        off += consumed;
    }
    Ok(nodes)
}

/// 计算某个字段在缓冲区中占用的总字节数。
fn field_len(buf: &[u8], off: usize) -> Option<usize> {
    let (key, ks) = read_varint(buf, off)?;
    let wire = (key & 7) as u8;
    let cursor = off + ks;
    let extra = match wire {
        0 => read_varint(buf, cursor)?.1,
        1 => 8,
        2 => {
            let (len, ls) = read_varint(buf, cursor)?;
            ls + len as usize
        }
        5 => 4,
        _ => return None,
    };
    Some(ks + extra)
}

fn nested_bytes(payload: &[u8], depth: usize) -> Option<(Vec<RvNode>, Kind)> {
    if depth + 1 >= RV_MAX_DEPTH || payload.len() < 2 {
        return None;
    }
    let text = try_utf8(payload);
    if let Ok(proto) = decode_protobuf(payload, depth + 1)
        && !proto.is_empty()
        && (text.is_none() || proto.len() >= 2)
    {
        return Some((proto, Kind::Protobuf));
    }
    if text.is_some() {
        return None;
    }
    if let Ok(jce) = decode_jce(payload, depth + 1)
        && !jce.is_empty()
    {
        return Some((jce, Kind::Jce));
    }
    None
}

/// 尝试按 protobuf 完整解析，失败返回 None。
pub fn try_decode_protobuf(buf: &[u8]) -> Option<Vec<RvNode>> {
    if buf.is_empty() {
        return None;
    }
    decode_protobuf(buf, 0).ok().filter(|n| !n.is_empty())
}

// ─────────────────────────── JCE ───────────────────────────

pub mod jce_type {
    pub const BYTE: u8 = 0;
    pub const SHORT: u8 = 1;
    pub const INT: u8 = 2;
    pub const LONG: u8 = 3;
    pub const FLOAT: u8 = 4;
    pub const DOUBLE: u8 = 5;
    pub const STRING1: u8 = 6;
    pub const STRING4: u8 = 7;
    pub const MAP: u8 = 8;
    pub const LIST: u8 = 9;
    pub const STRUCT_BEGIN: u8 = 10;
    pub const STRUCT_END: u8 = 11;
    pub const ZERO_TAG: u8 = 12;
    pub const SIMPLE_LIST: u8 = 13;
}

struct JceHead {
    tag: u32,
    ty: u8,
}

struct JceReader<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> JceReader<'a> {
    fn new(buf: &'a [u8], depth: usize) -> Self {
        Self { buf, pos: 0, depth }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn read_head(&mut self) -> Result<JceHead, DecodeError> {
        let b = *self.buf.get(self.pos).ok_or(err!("JCE: 头字节截断"))?;
        let ty = b & 0x0f;
        let mut tag = ((b >> 4) & 0x0f) as u32;
        let mut head_size = 1;
        if tag == 15 {
            tag = *self
                .buf
                .get(self.pos + 1)
                .ok_or(err!("JCE: 扩展 tag 截断"))? as u32;
            head_size = 2;
        }
        self.pos += head_size;
        Ok(JceHead { tag, ty })
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let b = *self.buf.get(self.pos).ok_or(err!("JCE: 数据截断"))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_u16(&mut self) -> Result<u16, DecodeError> {
        if self.pos + 2 > self.buf.len() {
            return Err(err!("JCE: 数据截断"));
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        if self.pos + 4 > self.buf.len() {
            return Err(err!("JCE: 数据截断"));
        }
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        if self.pos + 8 > self.buf.len() {
            return Err(err!("JCE: 数据截断"));
        }
        let v = u64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_f32(&mut self) -> Result<f32, DecodeError> {
        if self.pos + 4 > self.buf.len() {
            return Err(err!("JCE: 数据截断"));
        }
        let v = f32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_f64(&mut self) -> Result<f64, DecodeError> {
        if self.pos + 8 > self.buf.len() {
            return Err(err!("JCE: 数据截断"));
        }
        let v = f64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, DecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(err!("JCE: 数据截断"));
        }
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    /// 容器 size：带头字段（tag=0）；非法时兜底无头紧凑长度。
    fn read_size(&mut self) -> Result<usize, DecodeError> {
        let saved = self.pos;
        let attempt = (|| -> Result<usize, DecodeError> {
            let head = self.read_head()?;
            if head.tag != 0 {
                return Err(err!("JCE: size 字段 tag 非 0"));
            }
            match head.ty {
                jce_type::ZERO_TAG => Ok(0),
                jce_type::BYTE => Ok(self.read_u8()? as usize),
                jce_type::SHORT => Ok(self.read_u16()? as usize),
                jce_type::INT => {
                    let v = self.read_u32()?;
                    if v > 0x7fff_ffff {
                        return Err(err!("JCE: size 超出 int 范围"));
                    }
                    Ok(v as usize)
                }
                _ => Err(err!("JCE: 非法 size 类型")),
            }
        })();
        match attempt {
            Ok(v) => Ok(v),
            Err(_) => {
                self.pos = saved;
                self.read_size_compact()
            }
        }
    }

    fn read_size_compact(&mut self) -> Result<usize, DecodeError> {
        let b = *self.buf.get(self.pos).ok_or(err!("JCE: size 截断"))?;
        self.pos += 1;
        if b & 0x80 == 0 {
            Ok(b as usize)
        } else {
            let next = *self.buf.get(self.pos).ok_or(err!("JCE: size 截断"))?;
            self.pos += 1;
            Ok((((b & 0x7f) as usize) << 8) | next as usize)
        }
    }

    fn guard_size(&self, size: usize, min_bytes_per: usize) -> Result<(), DecodeError> {
        if size > MAX_CONTAINER_SIZE || size.saturating_mul(min_bytes_per) > self.remaining() + 2 {
            return Err(err!("JCE: 容器 size 不合理"));
        }
        Ok(())
    }

    fn read_top_level(&mut self) -> Result<Vec<RvNode>, DecodeError> {
        let mut nodes = Vec::new();
        while self.pos < self.buf.len() {
            let head = self.read_head()?;
            if head.ty == jce_type::STRUCT_END {
                break;
            }
            let value = self.read_value(head.ty)?;
            nodes.push(RvNode {
                tag: head.tag,
                value,
            });
        }
        Ok(nodes)
    }

    fn read_value(&mut self, ty: u8) -> Result<RvValue, DecodeError> {
        use jce_type::*;
        Ok(match ty {
            BYTE => RvValue::Int {
                raw: self.read_u8()? as u64,
                bits: 8,
                signed: true,
            },
            SHORT => RvValue::Int {
                raw: self.read_u16()? as u64,
                bits: 16,
                signed: true,
            },
            INT => RvValue::Int {
                raw: self.read_u32()? as u64,
                bits: 32,
                signed: true,
            },
            LONG => RvValue::Int {
                raw: self.read_u64()?,
                bits: 64,
                signed: true,
            },
            FLOAT => RvValue::Float(self.read_f32()? as f64),
            DOUBLE => RvValue::Float(self.read_f64()?),
            STRING1 => {
                let len = self.read_u8()? as usize;
                let bytes = self.read_bytes(len)?;
                RvValue::Str {
                    text: decode_utf8_lossy(&bytes),
                    bytes,
                }
            }
            STRING4 => {
                let len = self.read_u32()? as usize;
                let bytes = self.read_bytes(len)?;
                RvValue::Str {
                    text: decode_utf8_lossy(&bytes),
                    bytes,
                }
            }
            MAP => self.read_map()?,
            LIST => self.read_list()?,
            STRUCT_BEGIN => RvValue::Obj(self.read_struct()?),
            STRUCT_END => return Err(err!("JCE: 意外的 STRUCT_END")),
            ZERO_TAG => RvValue::Int {
                raw: 0,
                bits: 0,
                signed: false,
            },
            SIMPLE_LIST => self.read_simple_list()?,
            _ => return Err(err!("JCE: 未知类型")),
        })
    }

    fn read_struct(&mut self) -> Result<Vec<RvNode>, DecodeError> {
        let mut fields = Vec::new();
        while self.pos < self.buf.len() {
            let head = self.read_head()?;
            if head.ty == jce_type::STRUCT_END {
                break;
            }
            let value = self.read_value(head.ty)?;
            fields.push(RvNode {
                tag: head.tag,
                value,
            });
        }
        Ok(fields)
    }

    fn read_list(&mut self) -> Result<RvValue, DecodeError> {
        let size = self.read_size()?;
        self.guard_size(size, 1)?;
        let mut items = Vec::new();
        for _ in 0..size {
            let head = self.read_head()?;
            let value = self.read_value(head.ty)?;
            items.push(RvNode {
                tag: head.tag,
                value,
            });
        }
        Ok(RvValue::List(items))
    }

    fn read_map(&mut self) -> Result<RvValue, DecodeError> {
        let size = self.read_size()?;
        self.guard_size(size, 2)?;
        let mut entries = Vec::new();
        for _ in 0..size {
            let kh = self.read_head()?;
            let key = self.read_value(kh.ty)?;
            let vh = self.read_head()?;
            let value = self.read_value(vh.ty)?;
            entries.push((key, RvNode { tag: vh.tag, value }));
        }
        Ok(RvValue::Map(entries))
    }

    fn read_simple_list(&mut self) -> Result<RvValue, DecodeError> {
        let head = self.read_head()?;
        if head.ty != jce_type::BYTE {
            return Err(err!("JCE: SIMPLE_LIST 元素类型必须是 BYTE"));
        }
        let size = self.read_size()?;
        self.guard_size(size, 1)?;
        let bytes = self.read_bytes(size)?;
        let nested = nested_bytes(&bytes, self.depth);
        let (nested, nested_kind) = match nested {
            Some((n, k)) => (Some(n), Some(k)),
            None => (None, None),
        };
        Ok(RvValue::Bytes {
            bytes,
            nested,
            nested_kind,
        })
    }
}

/// 解码 JCE 顶层消息。
pub fn decode_jce(buf: &[u8], depth: usize) -> Result<Vec<RvNode>, DecodeError> {
    JceReader::new(buf, depth).read_top_level()
}

/// 尝试按 JCE 完整解析，失败返回 None。
pub fn try_decode_jce(buf: &[u8]) -> Option<Vec<RvNode>> {
    if buf.is_empty() {
        return None;
    }
    decode_jce(buf, 0).ok().filter(|n| !n.is_empty())
}

// ─────────────────── 长度前缀自动剥离 ───────────────────

/// 一个被识别出的长度前缀。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthPrefix {
    pub width: usize,
    pub endian: &'static str,
    pub value: usize,
    pub declared: &'static str,
}

fn read_uint(buf: &[u8], width: usize, be: bool) -> usize {
    let mut v = 0usize;
    if be {
        for &b in buf.iter().take(width) {
            v = v * 256 + b as usize;
        }
    } else {
        for &b in buf[..width].iter().rev() {
            v = v * 256 + b as usize;
        }
    }
    v
}

/// 枚举「数值自洽」的长度前缀候选，按可信度排序。
pub fn detect_length_prefixes(buf: &[u8]) -> Vec<LengthPrefix> {
    let mut out = Vec::new();
    for width in [4usize, 2, 1] {
        if buf.len() <= width {
            continue;
        }
        let endians: &[(&str, bool)] = if width == 1 {
            &[("be", true)]
        } else {
            &[("be", true), ("le", false)]
        };
        for (endian, be) in endians {
            let value = read_uint(buf, width, *be);
            let declared = if value == buf.len() {
                "total"
            } else if value == buf.len() - width {
                "payload"
            } else {
                continue;
            };
            if value == 0 {
                continue;
            }
            out.push(LengthPrefix {
                width,
                endian,
                value,
                declared,
            });
        }
    }
    out
}

/// 自动剥离长度前缀后按 protobuf（优先）/ JCE 解析。
pub fn try_decode_after_length_prefix(buf: &[u8]) -> Option<(Kind, Vec<RvNode>, LengthPrefix)> {
    for p in detect_length_prefixes(buf) {
        let body = &buf[p.width..];
        if let Some(n) = try_decode_protobuf(body) {
            return Some((Kind::Protobuf, n, p));
        }
        if let Some(n) = try_decode_jce(body) {
            return Some((Kind::Jce, n, p));
        }
    }
    None
}

/// 自动探测并解析：protobuf（含剥前缀）→ JCE（含剥前缀）。
pub fn decode_auto(buf: &[u8]) -> Option<(Kind, Vec<RvNode>, Option<LengthPrefix>)> {
    if let Some(n) = try_decode_protobuf(buf) {
        return Some((Kind::Protobuf, n, None));
    }
    if let Some(n) = try_decode_jce(buf) {
        return Some((Kind::Jce, n, None));
    }
    try_decode_after_length_prefix(buf).map(|(k, n, p)| (k, n, Some(p)))
}

// ─────────────────────────── 渲染 ───────────────────────────

fn hex(bytes: &[u8], max: usize) -> String {
    let take = bytes.len().min(max);
    let mut s = String::new();
    for b in &bytes[..take] {
        let _ = write!(s, "{b:02x}");
    }
    if bytes.len() > take {
        let _ = write!(s, "…(+{})", bytes.len() - take);
    }
    s
}

/// 一个值的一行紧凑描述（含类型标注与颜色，不含嵌套展开）。
pub fn value_summary(v: &RvValue) -> String {
    use crate::ui::{paint, palette};
    match v {
        RvValue::Int { raw, bits, signed } => {
            let d = rv_int_display(*raw, *bits, *signed);
            let ty = if *bits > 0 {
                format!("int{bits}")
            } else {
                "int".to_string()
            };
            match timestamp_range(*raw) {
                Some((unit, _ms)) => format!(
                    "{} {} {}",
                    paint(palette::num(), &d.to_string()),
                    paint(palette::ty_num(), &ty),
                    paint(palette::tag(), &format!("ts:{unit}"))
                ),
                None => format!(
                    "{} {}",
                    paint(palette::num(), &d.to_string()),
                    paint(palette::ty_num(), &ty)
                ),
            }
        }
        RvValue::Float(f) => format!(
            "{} {}",
            paint(palette::num(), &f.to_string()),
            paint(palette::ty_num(), "float")
        ),
        RvValue::Fixed { bytes, bits } => format!(
            "{} {}",
            paint(palette::num(), &format!("0x{}", hex(bytes, 16))),
            paint(palette::ty_num(), &format!("fixed{bits}"))
        ),
        RvValue::Str { text, .. } => format!(
            "{} {}",
            paint(
                palette::ty_text(),
                &format!("\"{}\"", text.replace('\n', "\\n"))
            ),
            paint(palette::ty_text(), "string")
        ),
        RvValue::Bytes {
            bytes,
            nested,
            nested_kind,
        } => match (nested, nested_kind) {
            (Some(n), Some(k)) => format!(
                "{} {}",
                paint(palette::ty_bytes(), &format!("bytes({}B)", bytes.len())),
                paint(palette::punct(), &format!("→ {k:?} {} 字段", n.len()))
            ),
            _ => {
                if let Some(t) = try_utf8(bytes) {
                    format!(
                        "{} {}",
                        paint(
                            palette::ty_text(),
                            &format!("\"{}\"", t.replace('\n', "\\n"))
                        ),
                        paint(palette::ty_text(), "string")
                    )
                } else {
                    format!(
                        "{} {}",
                        paint(palette::ty_bytes(), &format!("bytes({}B)", bytes.len())),
                        paint(palette::num(), &format!("0x{}", hex(bytes, 16)))
                    )
                }
            }
        },
        RvValue::Obj(f) => format!(
            "{} {}",
            paint(palette::ty_container(), "message"),
            paint(palette::dim(), &format!("{{ {} 字段 }}", f.len()))
        ),
        RvValue::List(items) => format!(
            "{} {}",
            paint(palette::ty_container(), "list"),
            paint(palette::dim(), &format!("[ {} 项 ]", items.len()))
        ),
        RvValue::Map(entries) => format!(
            "{} {}",
            paint(palette::ty_container(), "map"),
            paint(palette::dim(), &format!("{{ {} 对 }}", entries.len()))
        ),
    }
}

/// 把解码树渲染成带缩进、带类型颜色的多行文本（完整展开，不截断）。
pub fn render_tree(kind: Kind, nodes: &[RvNode]) -> Vec<String> {
    use crate::ui::{paint, palette};
    let mut lines = Vec::new();
    lines.push(format!(
        "{} {}",
        paint(palette::ty_container(), &format!("{kind:?}")),
        paint(palette::dim(), &format!("树（{} 顶层字段）", nodes.len()))
    ));
    render_nodes(nodes, 1, &mut lines);
    lines
}

fn render_nodes(nodes: &[RvNode], depth: usize, out: &mut Vec<String>) {
    use crate::ui::{paint, palette};
    let indent = "  ".repeat(depth);
    for n in nodes {
        let tag = paint(palette::tag(), &format!("#{}", n.tag));
        match &n.value {
            RvValue::Obj(fields) => {
                out.push(format!(
                    "{indent}{tag}: {} {}",
                    paint(palette::ty_container(), "message"),
                    paint(palette::dim(), &format!("{{ {} 字段 }}", fields.len()))
                ));
                render_nodes(fields, depth + 1, out);
            }
            RvValue::List(items) => {
                out.push(format!(
                    "{indent}{tag}: {} {}",
                    paint(palette::ty_container(), "list"),
                    paint(palette::dim(), &format!("[ {} 项 ]", items.len()))
                ));
                render_nodes(items, depth + 1, out);
            }
            RvValue::Map(entries) => {
                out.push(format!(
                    "{indent}{tag}: {} {}",
                    paint(palette::ty_container(), "map"),
                    paint(palette::dim(), &format!("{{ {} 对 }}", entries.len()))
                ));
                for (k, v) in entries {
                    out.push(format!(
                        "{indent}  {} {} {} {}",
                        value_summary(k),
                        paint(palette::punct(), "=>"),
                        paint(palette::tag(), &format!("#{}", v.tag)),
                        value_summary(&v.value)
                    ));
                }
            }
            RvValue::Bytes {
                nested: Some(nested),
                nested_kind,
                bytes,
            } => {
                out.push(format!(
                    "{indent}{tag}: {} {}",
                    paint(palette::ty_bytes(), &format!("bytes({}B)", bytes.len())),
                    paint(
                        palette::punct(),
                        &format!("→ {:?}", nested_kind.unwrap_or(Kind::Protobuf))
                    )
                ));
                render_nodes(nested, depth + 1, out);
            }
            other => out.push(format!("{indent}{tag}: {}", value_summary(other))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn varint_basic() {
        assert_eq!(read_varint(&[0x96, 0x01], 0), Some((150, 2)));
        assert_eq!(read_varint(&[0x00], 0), Some((0, 1)));
    }

    #[test]
    fn protobuf_decodes_simple_message() {
        // 08 96 01 12 02 68 69  => {1:150, 2:"hi"}
        let nodes = decode_protobuf(&hex("08960112026869"), 0).unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(matches!(nodes[0].value, RvValue::Int { raw: 150, .. }));
        match &nodes[1].value {
            RvValue::Bytes { bytes, .. } => assert_eq!(bytes, b"hi"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn protobuf_rejects_truncated() {
        assert!(try_decode_protobuf(&hex("0896")).is_none());
    }

    #[test]
    fn jce_decodes_string_and_int() {
        // JCE: STRING1 tag1 ("a"): head = 0x16, len 1, 'a' ; INT tag2 = 0x22 00000005
        let buf = hex("1601612200000005");
        let nodes = decode_jce(&buf, 0).unwrap();
        assert_eq!(nodes.len(), 2);
        match &nodes[0].value {
            RvValue::Str { text, .. } => assert_eq!(text, "a"),
            other => panic!("unexpected {other:?}"),
        }
        match &nodes[1].value {
            RvValue::Int {
                raw: 5,
                bits: 32,
                signed: true,
            } => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn jce_rejects_protobuf_bytes() {
        assert!(try_decode_jce(&hex("08960112026869")).is_none());
    }

    #[test]
    fn length_prefix_detected_and_stripped() {
        // total len = 4 + 4 payload; prefix 00 00 00 08
        let mut buf = vec![0, 0, 0, 8];
        buf.extend_from_slice(&hex("12026869")); // protobuf {2:"hi"}
        let p = detect_length_prefixes(&buf);
        assert!(
            p.iter()
                .any(|x| x.width == 4 && x.endian == "be" && x.declared == "total")
        );
        let (kind, nodes, _) = decode_auto(&buf).unwrap();
        assert_eq!(kind, Kind::Protobuf);
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn auto_prefers_protobuf() {
        let (k, _, _) = decode_auto(&hex("08960112026869")).unwrap();
        assert_eq!(k, Kind::Protobuf);
    }

    #[test]
    fn render_tree_includes_tags_and_nesting() {
        let nodes = decode_protobuf(&hex("089601"), 0).unwrap();
        let lines = render_tree(Kind::Protobuf, &nodes);
        assert!(lines[0].contains("Protobuf"));
        assert!(lines[1].contains("#1"));
        // 带颜色：字段号前应有 ANSI 起始序列。
        assert!(lines[1].contains("\u{1b}["));
    }

    #[test]
    fn render_tree_is_not_truncated() {
        // 100 个 tag=1 的 varint 字段，全部应被渲染（无「已截断」标记）。
        let mut buf = Vec::new();
        for i in 0..100u8 {
            buf.push(0x08);
            buf.push(i);
        }
        let nodes = decode_protobuf(&buf, 0).unwrap();
        assert_eq!(nodes.len(), 100);
        let lines = render_tree(Kind::Protobuf, &nodes);
        assert_eq!(lines.len(), 1 + 100);
        assert!(!lines.iter().any(|l| l.contains("截断")));
    }

    #[test]
    fn two_complement_signed() {
        assert_eq!(two_complement(0xff, 8), -1);
        assert_eq!(two_complement(0xffff_ffff, 32), -1);
        assert_eq!(two_complement(5, 32), 5);
    }

    #[test]
    fn zigzag_roundtrip() {
        assert_eq!(zigzag_decode(0), 0);
        assert_eq!(zigzag_decode(1), -1);
        assert_eq!(zigzag_decode(2), 1);
    }
}
