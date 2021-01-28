#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
use macos::{Context, Verifier};

pub struct CodeSignVerifier(Verifier);

pub struct SignatureContext(Context);

///
/// Represents an Issuer or Subject name with the following fields:
/// `common_name`: OID 2.5.4.3
/// `organization_name`: OID 2.5.4.10
/// `organization_unit_name`: OID 2.5.4.11
/// `country_name`: OID 2.5.4.6
///
#[derive(Debug)]
pub struct Name {
    pub common_name: Option<String>,       // 2.5.4.3
    pub organization: Option<String>,      // 2.5.4.10
    pub organization_unit: Option<String>, // 2.5.4.11
    pub country: Option<String>,           // 2.5.4.6
}

#[derive(Debug)]
pub enum Error {
    Unsigned,         // The binary file didn't have any singature
    OsError(i32),     // Warps an inner provider error code
    InvalidPath,      // The provided path was malformed
    LeafCertNotFound, // Unable to fetch certificate information
    #[cfg(target_os = "macos")]
    CFError(String),
}

impl CodeSignVerifier {
    /// Create a verifier for a binary at a given path.
    /// On macOS it can be either a binary or an application package.
    pub fn for_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        Verifier::for_file(path).map(|v| CodeSignVerifier(v))
    }

    /// Create a verifier for a running application by PID.
    /// On Windows it will get the full path to the running application first.
    pub fn for_pid(pid: i32) -> Result<Self, Error> {
        Verifier::for_pid(pid).map(|v| CodeSignVerifier(v))
    }

    /// Perform the verification itself.
    /// On macOS the verification uses the Security framework with "anchor trusted" as the requirement.
    /// On Windows the verification uses WinTrust and the `WINTRUST_ACTION_GENERIC_VERIFY_V2` action.
    pub fn verify(self) -> Result<SignatureContext, Error> {
        self.0.verify().map(|c| SignatureContext(c))
    }
}

impl SignatureContext {
    /// Retrieve the subject name on the leaf certificate
    pub fn subject_name(&self) -> Name {
        self.0.subject_name()
    }

    /// Retrieve the issuer name on the leaf certificate
    pub fn issuer_name(&self) -> Name {
        self.0.issuer_name()
    }

    /// Retrieve the leaf certificate serial number
    pub fn serial(&self) -> Option<String> {
        self.0.serial()
    }

    /// Compute the sha1 thumbprint of the leaf certificate
    pub fn sha1_thumbprint(&self) -> String {
        self.0.sha1_thumbprint()
    }

    /// Compute the sha256 thumbprint of the leaf certificate
    pub fn sha256_thumbprint(&self) -> String {
        self.0.sha256_thumbprint()
    }
}

#[cfg(test)]
mod tests {
    use crate::Error;

    #[test]
    fn test_signed() {
        let verifier = super::CodeSignVerifier::for_file("/sbin/ping").unwrap(); // Should always be present on macOS
        let ctx = verifier.verify().unwrap(); // Should always be signed

        // If those values begin to fail, Apple probably changed their certficate
        assert_eq!(
            ctx.subject_name().organization.as_deref(),
            Some("Apple Inc.")
        );

        assert_eq!(
            ctx.issuer_name().organization_unit.as_deref(),
            Some("Apple Certification Authority")
        );

        assert_eq!(
            ctx.sha1_thumbprint(),
            "013e2787748a74103d62d2cdbf77a1345517c482"
        );
    }

    #[test]
    fn test_unsigned() {
        let path = std::env::args().next().unwrap(); // own path, always unsigned and present

        assert!(matches!(
            super::CodeSignVerifier::for_file(path).unwrap().verify(),
            Err(Error::Unsigned)
        ));
    }
}
