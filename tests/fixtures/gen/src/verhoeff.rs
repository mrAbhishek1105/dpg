//! Verhoeff checksum algorithm for Aadhaar generation and validation.

// Dihedral group D5 multiplication table
const D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

// Permutation table
const P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

// Inverse table
const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/// Validates whether a numerical string has a valid Verhoeff checksum.
pub fn validate_verhoeff(num_str: &str) -> bool {
    let mut c = 0;
    let digits: Vec<u8> = num_str
        .chars()
        .filter_map(|ch| ch.to_digit(10).map(|d| d as u8))
        .collect();

    if digits.len() != num_str.len() || digits.is_empty() {
        return false;
    }

    // Process from right to left (index 0 is check digit at right)
    for (i, &digit) in digits.iter().rev().enumerate() {
        let p_val = P[i % 8][digit as usize];
        c = D[c as usize][p_val as usize];
    }

    c == 0
}

/// Computes the Verhoeff check digit for an input prefix string of digits.
pub fn compute_check_digit(prefix: &str) -> Option<u8> {
    let mut c = 0;
    let digits: Vec<u8> = prefix
        .chars()
        .filter_map(|ch| ch.to_digit(10).map(|d| d as u8))
        .collect();

    if digits.len() != prefix.len() || digits.is_empty() {
        return None;
    }

    // Positions for check digit calculation: check digit will be at index 0,
    // so prefix digits are at indices 1, 2, 3...
    for (i, &digit) in digits.iter().rev().enumerate() {
        let p_val = P[(i + 1) % 8][digit as usize];
        c = D[c as usize][p_val as usize];
    }

    Some(INV[c as usize])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_verhoeff_known_numbers() {
        // Test with known Verhoeff-valid numbers
        assert!(validate_verhoeff("2363"));
        assert!(!validate_verhoeff("2364"));

        let check = compute_check_digit("236").expect("check digit");
        assert_eq!(check, 3);
    }
}
