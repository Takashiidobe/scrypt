use std::mem::size_of;

#[link(name = "scrypt")]
extern "C" {
    pub fn crypto_scrypt(
        password: *const u8,
        password_len: usize,
        salt: *const u8,
        salt_len: usize,
        N: u64,
        r: u32,
        p: u32,
        buf: *mut u8,
        buf_len: usize,
    ) -> ::std::os::raw::c_int;
}

/// The Scrypt parameter values
#[derive(Clone, Debug)]
pub struct ScryptHasher<'a> {
    /// Number of iterations
    n: u64,

    /// Block size for the underlying hash
    r: u32,

    /// Parallelization factor
    p: u32,

    /// Salt
    salt: &'a [u8],
}

impl ScryptHasher<'_> {
    /// Create a ScryptHasher instance with the provided salt.
    pub fn with_salt(n: u64, r: u32, p: u32, salt: &[u8]) -> ScryptHasher {
        // r should be at least 1.
        assert!(r > 0);
        // p should be at least 1
        assert!(p > 0);
        // n must be at least 2.
        assert!(n >= 2);
        // n must be a power of 2.
        assert!(n & (n - 1) != 0);
        // r and p must be less than the max size of a u32.
        assert!(
            size_of::<usize>() >= size_of::<u32>()
                || (r <= std::usize::MAX as u32 && p < std::usize::MAX as u32)
        );

        ScryptHasher { n, r, p, salt }
    }

    /// Return the hashed scrypt value in buf.
    pub fn hash(&mut self, data: &[u8], buf: &mut [u8]) {
        unsafe {
            crypto_scrypt(
                data.as_ptr(),
                data.len(),
                self.salt.as_ptr(),
                self.salt.len(),
                self.n,
                self.r,
                self.p,
                buf.as_mut_ptr(),
                buf.len(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate hex;

    use super::*;
    use tests::hex::{decode, encode};

    const SALT: &str = "9286F768BE82A5DB";
    const PASSWORD: &str = "password";

    fn hash(buf: &mut [u8], salt: &str, password: &str) {
        let salt = &decode(salt).unwrap();
        let mut params = ScryptHasher::with_salt(2, 8, 1, &salt);
        params.hash(password.as_bytes(), buf);
    }

    fn test_eq(left: &str, right: &[u8]) {
        assert_eq!(left, encode(right.as_ref()));
    }

    fn scrypt_128_test(res: &str, salt: &str, password: &str) {
        let mut buf = [0u8; 16];
        hash(&mut buf, salt, password);

        test_eq(res, &buf);
    }

    fn scrypt_256_test(res: &str, salt: &str, password: &str) {
        let mut buf = [0u8; 32];
        hash(&mut buf, salt, password);

        test_eq(res, &buf);
    }

    fn scrypt_512_test(res: &str, salt: &str, password: &str) {
        let mut buf = [0u8; 64];
        hash(&mut buf, salt, password);

        test_eq(res, &buf);
    }

    #[test]
    fn test_scrypt_128() {
        scrypt_128_test("02e964b10404d6abdbe85b560789ff18", SALT, PASSWORD);
    }

    #[test]
    fn test_scrypt_256() {
        scrypt_256_test(
            "02e964b10404d6abdbe85b560789ff18c7749705034bfc8f69ec665fc19d7979",
            SALT,
            PASSWORD,
        );
    }

    #[test]
    fn test_scrypt_512() {
        scrypt_512_test(
            "02e964b10404d6abdbe85b560789ff18c7749705034bfc8f69ec665fc19d79797c920f07460d4e33d8322500fb774b208f1ab874d8f7518ef51cb06426e0edc6",
            SALT,
            PASSWORD,
        );
    }
}
