#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
use macos::{Context, Verifier};
#[cfg(windows)]
use windows::{Context, Verifier};

///
/// Used to verify the validity of a code signature
///
pub struct CodeSignVerifier(Verifier);

///
/// Used to extract additional information from the signing leaf certificate
///
pub struct SignatureContext(Context);

///
/// Represents an Issuer or Subject name with the following fields:
///
/// # Fields
///
/// `common_name`: OID 2.5.4.3
///
/// `organization`: OID 2.5.4.10
///
/// `organization_unit`: OID 2.5.4.11
///
/// `country`: OID 2.5.4.6
///
#[derive(Debug, PartialEq)]
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
    #[cfg(windows)]
    IoError(std::io::Error),
}

impl CodeSignVerifier {
    /// Create a verifier for a binary at a given path.
    /// On macOS it can be either a binary or an application package.
    pub fn for_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        Verifier::for_file(path).map(|v| CodeSignVerifier(v))
    }

    /// Create a verifier for a running application by PID.
    /// On Windows it will get the full path to the running application first.
    /// This can be used for e.g. verifying the app on the other end of a pipe.
    pub fn for_pid(pid: i32) -> Result<Self, Error> {
        Verifier::for_pid(pid).map(|v| CodeSignVerifier(v))
    }

    /// Perform the verification itself.
    /// On macOS the verification uses the Security framework with "anchor trusted" as the requirement.
    /// On Windows the verification uses WinTrust and the `WINTRUST_ACTION_GENERIC_VERIFY_V2` action.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use codesign_verify::CodeSignVerifier;
    ///
    /// CodeSignVerifier::for_file("C:/Windows/explorer.exe").unwrap().verify().unwrap();
    /// ```
    pub fn verify(self) -> Result<SignatureContext, Error> {
        self.0.verify().map(|c| SignatureContext(c))
    }
}

impl SignatureContext {
    /// Retrieve the subject name on the leaf certificate
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use codesign_verify::CodeSignVerifier;
    ///
    /// let ctx = CodeSignVerifier::for_file("C:/Windows/explorer.exe").unwrap().verify().unwrap();
    /// assert_eq!(
    ///    ctx.subject_name().organization.as_deref(),
    ///    Some("Microsoft Corporation")
    /// );
    ///
    /// ```
    pub fn subject_name(&self) -> Name {
        self.0.subject_name()
    }

    /// Retrieve the issuer name on the leaf certificate
    pub fn issuer_name(&self) -> Name {
        self.0.issuer_name()
    }

    /// Compute the sha1 thumbprint of the leaf certificate
    pub fn sha1_thumbprint(&self) -> String {
        self.0.sha1_thumbprint()
    }

    /// Compute the sha256 thumbprint of the leaf certificate
    pub fn sha256_thumbprint(&self) -> String {
        self.0.sha256_thumbprint()
    }

    /// Retrieve the leaf certificate serial number
    pub fn serial(&self) -> Option<String> {
        self.0.serial()
    }
}

#[cfg(test)]
mod tests {
    use crate::Error;

    #[test]
    #[cfg(target_os = "macos")]
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
    #[cfg(windows)]
    fn test_signed() {
        let path = format!("{}/explorer.exe", std::env::var("windir").unwrap()); // Should always be present on Windows
        let verifier = super::CodeSignVerifier::for_file(path).unwrap();
        let ctx = verifier.verify().unwrap(); // Should always be signed

        // If those values begin to fail, Microsoft probably changed their certficate
        assert_eq!(
            ctx.subject_name().organization.as_deref(),
            Some("Microsoft Corporation")
        );

        assert_eq!(
            ctx.issuer_name().common_name.as_deref(),
            Some("Microsoft Windows Production PCA 2011")
        );

        assert_eq!(
            ctx.sha1_thumbprint(),
            "58fd671e2d4d200ce92d6e799ec70df96e6d2664"
        );

        assert_eq!(
            ctx.serial().as_deref(),
            Some("330000041331bc198807a90774000000000413")
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
