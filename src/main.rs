mod qrcode;
mod totp;

fn main() {
    let url = qrcode::extract_totp_uri(String::from("/Users/p0n002h/tmp/test.png")).unwrap();
    let spec = totp::TOTPSpec::new(url);
    println!("{}", spec.get_otp());
}
