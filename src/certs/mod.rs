// Function to check if certificate is in .der or .pem depending on its contents
pub fn identify_cert(buf:&[u8]) -> String {
    // Pem certificates will start with this byte content
    let pem_start: &[u8] = &[45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45];

    // Compare bytes and return result
    if buf == pem_start {
        return "pem".to_string();
    } else {
        return "der".to_string();
    }
}