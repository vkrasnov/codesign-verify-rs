mod context;
#[allow(non_upper_case_globals)]
mod sec_sys;

use super::Error;
use sec_sys::*;

pub(crate) struct Verifier(SecCodeKind);
pub(crate) use context::Context;

#[derive(Debug)]
enum SecCodeKind {
    Static(SecStaticCode), // Static code is created for files on disk
    Dynamic(SecCode),      // Regular code is created for a guest pid
}

impl Verifier {
    /// Retrieve the code object for the process with the given pid
    pub fn for_pid(pid: i32) -> Result<Self, Error> {
        let mut sec: SecCodeRef = std::ptr::null_mut();

        let attributes = unsafe {
            CFDictionary::from_CFType_pairs(&[(
                CFString::wrap_under_get_rule(kSecGuestAttributePid),
                CFNumber::from(pid),
            )])
        };

        unsafe {
            match SecCodeCopyGuestWithAttributes(
                std::ptr::null_mut(),
                attributes.as_concrete_TypeRef(),
                SecCSFlags::kSecCSDefaultFlags,
                Some(&mut sec),
            ) {
                sec_sys::errSecSuccess if !sec.is_null() => Ok(Verifier(SecCodeKind::Dynamic(
                    SecCode::wrap_under_create_rule(sec),
                ))),
                err => Err(Error::OsError(err)),
            }
        }
    }

    /// Retrieve the code object for the file at the target location
    pub fn for_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let mut sec: SecStaticCodeRef = std::ptr::null_mut();
        let url = CFURL::from_path(path.as_ref(), false).ok_or(Error::InvalidPath)?;

        unsafe {
            match SecStaticCodeCreateWithPath(
                url.as_concrete_TypeRef(),
                SecCSFlags::kSecCSDefaultFlags,
                Some(&mut sec),
            ) {
                sec_sys::errSecSuccess if !sec.is_null() => Ok(Verifier(SecCodeKind::Static(
                    SecStaticCode::wrap_under_create_rule(sec),
                ))),
                err => Err(Error::OsError(err)),
            }
        }
    }

    pub fn verify(&self) -> Result<Context, Error> {
        self.check_validity("anchor trusted")?; // This is the most generic verification
        let sec_info = self.get_code_singing_info()?;
        let cert_key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoCertificates) };

        let certs_ref = sec_info
            .find(cert_key.as_CFTypeRef())
            .ok_or(Error::LeafCertNotFound)?;

        let certs = unsafe { CFArray::<SecCertificate>::wrap_under_get_rule(*certs_ref as _) };
        let leaf_cert = certs.get(0).ok_or(Error::LeafCertNotFound)?;

        Ok(Context::new(leaf_cert.as_concrete_TypeRef()))
    }

    /// Retreive a dictionary of various pieces of information from a code signature.
    fn get_code_singing_info(&self) -> Result<CFDictionary, Error> {
        let mut dict: CFDictionaryRef = std::ptr::null_mut();

        let sec = match &self.0 {
            SecCodeKind::Static(sec) => sec.as_concrete_TypeRef(),
            SecCodeKind::Dynamic(sec) => sec.as_CFTypeRef() as _, // Dynamic will be implicitly converted to static
        };

        unsafe {
            match SecCodeCopySigningInformation(
                sec,
                SecCSFlags::kSecCSSigningInformation,
                Some(&mut dict),
            ) {
                sec_sys::errSecSuccess if !dict.is_null() => {
                    Ok(CFDictionary::wrap_under_create_rule(dict))
                }
                err => Err(Error::OsError(err)),
            }
        }
    }

    fn check_validity(&self, requirement: &str) -> Result<(), Error> {
        let mut req: SecRequirementRef = std::ptr::null_mut();
        let mut err: CFErrorRef = std::ptr::null_mut();

        // Generate a new requirement object using the Apple [Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html#//apple_ref/doc/uid/TP40005929-CH5-SW1)
        let req = unsafe {
            match SecRequirementCreateWithStringAndErrors(
                CFString::new(requirement).as_concrete_TypeRef(),
                SecCSFlags::kSecCSDefaultFlags,
                Some(&mut err),
                Some(&mut req),
            ) {
                sec_sys::errSecSuccess if !req.is_null() => {
                    SecRequirement::wrap_under_create_rule(req)
                }
                status => {
                    if !err.is_null() {
                        return Err(err.into());
                    } else {
                        return Err(Error::OsError(status));
                    }
                }
            }
        };

        let status = match &self.0 {
            SecCodeKind::Static(sec) => unsafe {
                SecStaticCodeCheckValidityWithErrors(
                    sec.as_concrete_TypeRef(),
                    SecCSFlags::kSecCSDefaultFlags,
                    req.as_concrete_TypeRef(),
                    Some(&mut err),
                )
            },
            SecCodeKind::Dynamic(sec) => unsafe {
                SecCodeCheckValidityWithErrors(
                    sec.as_concrete_TypeRef(),
                    SecCSFlags::kSecCSDefaultFlags,
                    req.as_concrete_TypeRef(),
                    Some(&mut err),
                )
            },
        };

        match status {
            sec_sys::errSecSuccess => Ok(()),
            sec_sys::errSecCSUnsigned => Err(Error::Unsigned),
            status => {
                if !err.is_null() {
                    Err(err.into())
                } else {
                    Err(Error::OsError(status))
                }
            }
        }
    }
}

impl From<CFErrorRef> for Error {
    fn from(err: CFErrorRef) -> Self {
        if err.is_null() {
            panic!()
        }
        unsafe {
            let err = CFError::wrap_under_get_rule(err);
            Error::CFError(format!(
                "{:?}",
                CFDictionary::wrap_under_create_rule(CFErrorCopyUserInfo(
                    err.as_concrete_TypeRef()
                )),
            ))
        }
    }
}
