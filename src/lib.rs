use data_encoding::{BASE32};
use std::time::{SystemTime, UNIX_EPOCH};
use core::fmt;
use hmacsha1;

const TIME_PERIOD: u64 = 30;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TOTPErrorReason {
    InvalidKey,
    InvalidTime
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TOTPError {
    reason: TOTPErrorReason
}

impl fmt::Display for TOTPError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.reason {
            TOTPErrorReason::InvalidKey => f.write_str("Provided key could not be BASE32 decoded"),
            TOTPErrorReason::InvalidTime => f.write_str("System time set to before UNIX epoch")
        }
    }
}

fn epoch() -> Result<u64, TOTPError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| TOTPError { reason: TOTPErrorReason::InvalidTime })
}

fn hash_time(key: &[u8], time: u64) -> [u8; 20] {
    hmacsha1::hmac_sha1(key, &time.to_be_bytes())
}

fn key_to_bytes(key: &str) -> Result<Vec<u8>, TOTPError> {
    BASE32
        .decode(key.as_bytes())
        .map_err(|_| TOTPError { reason: TOTPErrorReason::InvalidKey })
}

fn hash_to_code(hash: [u8; 20]) -> u64 {
    let offset = (hash[19] & 0xf) as usize;

    (hash[offset + 0] as u64 & 0x7f) << 24 |
    (hash[offset + 1] as u64 & 0xff) << 16 |
    (hash[offset + 2] as u64 & 0xff) << 08 |
    (hash[offset + 3] as u64 & 0xff)
}

fn last_six_digits_of_num(num: u64) -> u64 {
    num % 1000000
}

fn code_to_str(code: u64) -> String {
    format!("{:0>6}", last_six_digits_of_num(code))  // Format into 6 digit number
}

pub fn otp(key: &str) -> Result<String, TOTPError> {
    otp_with_time(key, epoch()?)
}

pub fn otp_with_time(key: &str, epoch: u64) -> Result<String, TOTPError> {
    let time_hash = hash_time(key_to_bytes(key)?.as_slice(), begin_period_with_time(epoch));
    let code = hash_to_code(time_hash);
    let code_str = code_to_str(code);
    Ok(code_str)
}

pub fn begin_period() -> Result<u64, TOTPError> {
    Ok(begin_period_with_time(epoch()?))
}

pub fn begin_period_with_time(time: u64) -> u64 {
    time / TIME_PERIOD
}

pub fn end_period() -> Result<u64, TOTPError> {
    Ok(end_period_with_time(epoch()?))
}

pub fn end_period_with_time(time: u64) -> u64 {
    begin_period_with_time(time) + TIME_PERIOD
}

#[cfg(test)]
mod tests {
    use crate::{otp_with_time};

    #[test]
    fn generate_valid_otp() {
        const KEY: &str = "TKI3J4MD6HBVVLAB";
        const TIME: u64 = 1578082942;
        const RESULT: &str = "075767";

        assert_eq!(otp_with_time(KEY, TIME).unwrap(), RESULT);
    }
}
