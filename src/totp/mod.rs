extern crate data_encoding;
extern crate ring;
extern crate url;

use data_encoding::BASE32;
use ring::hmac;
use std::borrow::Cow::Borrowed;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use std::convert::From;

#[derive(Default, Debug)]
pub struct TOTPSpec {
    secret: Vec<u8>,
    period: u32,
    digits: u8,
    algorithm: String,
    issuer: String,
}

struct Bytes([u8; 8]);

impl TOTPSpec {
    pub fn default() -> TOTPSpec {
        TOTPSpec {
            secret: Vec::new(),
            period: 30,
            digits: 6,
            algorithm: String::from("SHA1"),
            issuer: String::from(""),
        }
    }

    /// Get a new TOTPSpec object based on a url.Url object.
    pub fn new(u: Url) -> Self {
        if u.host_str() != Some("totp") {
            eprintln!("Unsupported URL format");
            process::exit(1);
        }

        let query_string = u.query_pairs();
        let mut spec = TOTPSpec::default();

        // Sample url
        // otpauth://totp/otplib-website:otplib-demo-user?
        // secret=H4ZWJCQZEREL2IE2&period=30&digits=6
        // &algorithm=SHA1&issuer=otplib-website
        for qs in query_string {
            match qs {
                (Borrowed("secret"), x) => {
                    let mut s = x.into_owned();
                    pad_string_to_base32(&mut s);

                    spec.secret = BASE32.decode(s.as_bytes()).unwrap();
                }
                (Borrowed("period"), x) => {
                    spec.period = x.into_owned().parse().unwrap();
                    if spec.period < 1 {
                        spec.period = 30
                    }
                }
                (Borrowed("algorithm"), x) => {
                    spec.algorithm = x.into_owned();
                }
                (Borrowed("digits"), x) => {
                    spec.digits = x.into_owned().parse().unwrap();
                    if spec.digits < 6 || spec.digits > 8 {
                        // default to 6 for any invalid or unsupported
                        // digit count.
                        spec.digits = 6
                    }
                }
                (Borrowed("issuer"), x) => {
                    spec.issuer = x.into_owned();
                }
                (_, _) => {}
            }
        }

        spec
    }

    /// Utility method that reads the state of the spec and generates the
    /// current token.
    pub fn get_otp(&self) -> String {
        get_otp(&self, get_counter_as_bytes(&self))
    }
}

/// Implement the from trait to convert a u32 into a big endian
/// representation where the bytearray's lower index will have the
/// highest significant value. Eg: 1 -> [0, 0, 0, 0, 0, 0, 0, 1]
impl From<u32> for Bytes {
    fn from(v: u32) -> Bytes {
        let mut c = v;
        let mut x = [0u8; 8];
        for i in 0..8 {
            x[7 - i] = (c & 0xff) as u8;
            c = c >> 8;
        }
        Bytes(x)
    }
}

/// Get the counter value at the current time as the interval number
/// which will be used to calculate the hash for the HOTP.
fn get_counter_as_bytes(spec: &TOTPSpec) -> u32 {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    t.as_secs() as u32 / spec.period
}

/// Get the OTP for the based on spec.
pub fn get_otp(spec: &TOTPSpec, counter: u32) -> String {
    // At the moment, only SHA1 is supported.
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, spec.secret.as_slice());
    let tag = hmac::sign(&key, &Bytes::from(counter).0);

    // The offset as the 4 bits from the low-order bits. For example
    // if the output of the signature is 160 bits, we use the last
    // 4 bits.
    let offset: usize = (tag.as_ref()[19] & 0x0f) as usize;

    let mut h: u32 = ((tag.as_ref()[offset] & 0x7f) as u32) << 24;
    h = h | ((tag.as_ref()[offset + 1] & 0xff) as u32) << 16;
    h = h | ((tag.as_ref()[offset + 2] & 0xff) as u32) << 8;
    h = h | ((tag.as_ref()[offset + 3] & 0xff) as u32);

    // Format the otp with left padding if the modulo is less than
    // the required digits.
    format!(
        "{:0w$}",
        (h % 10u32.pow(spec.digits as u32)),
        w = spec.digits as usize
    )
}

/// Pad the secret to have the length divisible by 8 for it to be
/// decoded as base32.
fn pad_string_to_base32(s: &mut String) {
    let mut pad_len = 0;
    if s.len() % 8 != 0 {
        pad_len = 8 - s.len() % 8;
    }

    for _ in 0..pad_len {
        s.push('=');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sample url
    // otpauth://totp/otplib-website:otplib-demo-user?
    // secret=H4ZWJCQZEREL2IE2&period=30&digits=6
    // &algorithm=SHA1&issuer=otplib-website
    #[test]
    fn rfc4226_test_counter_1() {
        let mut spec = TOTPSpec::default();
        spec.secret = "12345678901234567890".as_bytes().to_vec();
        let x = get_otp(&spec, 1);
        assert_eq!(x, "287082");
    }

    #[test]
    fn rfc4226_test_counter_9() {
        let mut spec = TOTPSpec::default();
        spec.secret = "12345678901234567890".as_bytes().to_vec();
        let x = get_otp(&spec, 9);
        assert_eq!(x, "520489");
    }

    #[test]
    fn totp_test_with_url() {
        let u = Url::parse("otpauth://totp/test:user?secret=JBSWY3DPEHPK3PXP").unwrap();
        let spec = TOTPSpec::new(u);
        assert_eq!(get_otp(&spec, 53273637), "927328");
    }

    #[test]
    fn int_to_bytes() {
        let mut v = [0u8; 8];
        v[7] = 0x39;
        v[6] = 0x5;
        assert_eq!(Bytes::from(1337).0, v);
    }

    #[test]
    fn pad_bytes_test() {
        let mut s = String::from("totp");
        pad_string_to_base32(&mut s);
        assert_eq!(String::from("totp===="), s);
    }

    #[test]
    fn totp_spec_default() {
        let spec = TOTPSpec::default();
        assert_eq!(spec.digits, 6);
        assert_eq!(spec.period, 30);
        assert_eq!(spec.algorithm, "SHA1");
    }

    #[test]
    fn totp_spec_parse() {
        let u = Url::parse("otpauth://totp/test:user?digits=3&secret=JBSWY3DPEHPK3PXP").unwrap();
        let spec = TOTPSpec::new(u);
        assert_eq!(spec.digits, 6);
        assert_eq!(spec.period, 30);
    }
}
