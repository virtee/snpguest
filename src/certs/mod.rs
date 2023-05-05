pub enum CertEncryption {
    PEM,
    DER
}

// Function to check if certificate is in .der or .pem depending on its contents
pub fn identify_cert(buf:&[u8]) -> CertEncryption {
    // Pem certificates will start with this byte content
    const PEM_START: &[u8] = &[45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45, 45, 45, 45, 45];

    match buf {
        PEM_START => CertEncryption::PEM,
        _ => CertEncryption::DER
    }
}