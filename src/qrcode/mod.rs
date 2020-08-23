use bardecoder;
use image;
use url::Url;

/// extract_totp_uri extracts the uri identifier from the QRcode
/// required to generate a TOTP. This contains the secret, tick
/// period, digits in the top string, algorithm used to create the
/// hash for the HOTP core and the issuer as a metadata.
pub fn extract_totp_uri(file_path: String) -> Option<Url> {
    let img = match image::open(file_path) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return None;
        }
    };

    let decoder = bardecoder::default_decoder();
    let ref secrets = decoder.decode(&img);
    let u = match secrets.len() > 0 {
        true => secrets[0].as_ref().unwrap(),
        false => {
            eprintln!("No OTP url found in the image");
            return None;
        }
    };
    let parsed_url = match Url::parse(u) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Invalid url: {}", e);
            return None;
        }
    };

    return Some(parsed_url);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_parse_success() {
        let f = String::from("./testdata/test.png");
        let u = extract_totp_uri(f).unwrap();
        let s = Url::parse("otpauth://totp/otplib-website:otplib-demo-user?secret=H4ZWJCQZEREL2IE2&period=30&digits=6&algorithm=SHA1&issuer=otplib-website").unwrap();
        assert_eq!(u, s);
    }

    #[test]
    fn test_totp_parse_empty() {
        let f = String::from("./testdata/emtpy.png");
        let u = extract_totp_uri(f);
        assert_eq!(u.is_none(), true);
    }
}
