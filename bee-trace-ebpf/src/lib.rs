#![no_std]

// This file exists to enable the library target.

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    #[test]
    fn sanity() {
        assert_eq!(2 + 2, 4);
    }
}
