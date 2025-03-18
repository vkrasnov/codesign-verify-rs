pub use core_foundation::array::{CFArray, CFArrayRef};
pub use core_foundation::base::{CFType, CFTypeID, OSStatus, TCFType};
pub use core_foundation::data::{CFData, CFDataRef};
pub use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
pub use core_foundation::error::{CFError, CFErrorRef};
pub use core_foundation::number::CFNumber;
pub use core_foundation::string::{CFString, CFStringRef};
pub use core_foundation::url::{CFURLRef, CFURL};
pub use core_foundation::{declare_TCFType, impl_CFTypeDescription, impl_TCFType};

pub const errSecSuccess: OSStatus = 0;
pub const errSecCSUnsigned: OSStatus = -67062;

pub struct __SecCode {}
pub struct __SecStaticCode {}
pub struct __SecCertificate {}
pub struct __SecRequirement {}

pub type SecCertificateRef = *const __SecCertificate;
pub type SecCodeRef = *const __SecCode;
pub type SecStaticCodeRef = *const __SecStaticCode;
pub type SecRequirementRef = *const __SecRequirement;

extern "C" {
    pub fn SecCertificateGetTypeID() -> CFTypeID;
    pub fn SecCodeGetTypeID() -> CFTypeID;
    pub fn SecStaticCodeGetTypeID() -> CFTypeID;
    pub fn SecRequirementGetTypeID() -> CFTypeID;
}

declare_TCFType!(SecCertificate, SecCertificateRef);
impl_TCFType!(SecCertificate, SecCertificateRef, SecCertificateGetTypeID);
impl_CFTypeDescription!(SecCertificate);

declare_TCFType!(SecCode, SecCodeRef);
impl_TCFType!(SecCode, SecCodeRef, SecCodeGetTypeID);
impl_CFTypeDescription!(SecCode);

declare_TCFType!(SecStaticCode, SecStaticCodeRef);
impl_TCFType!(SecStaticCode, SecStaticCodeRef, SecStaticCodeGetTypeID);
impl_CFTypeDescription!(SecStaticCode);

declare_TCFType!(SecRequirement, SecRequirementRef);
impl_TCFType!(SecRequirement, SecRequirementRef, SecRequirementGetTypeID);
impl_CFTypeDescription!(SecRequirement);

#[repr(u32)]
#[allow(dead_code, non_camel_case_types, clippy::enum_variant_names)]
pub enum SecCSFlags {
    kSecCSDefaultFlags = 0,
    kSecCSSigningInformation = 1 << 1,
    kSecCSConsiderExpiration = 1 << 31,
    kSecCSEnforceRevocationChecks = 1 << 30,
    kSecCSCheckTrustedAnchors = 1 << 27,
    kSecCSNoNetworkAccess = 1 << 29,
    kSecCSReportProgress = 1 << 28,
    kSecCSQuickCheck = 1 << 26,
}

#[allow(improper_ctypes)]
#[cfg_attr(
    any(target_os = "macos", target_os = "ios"),
    link(name = "Security", kind = "framework")
)]
extern "C" {
    pub fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: SecCSFlags,
        guest: Option<&mut SecCodeRef>,
    ) -> OSStatus;

    pub fn SecStaticCodeCreateWithPath(
        path: CFURLRef,
        flags: SecCSFlags,
        static_code: Option<&mut SecStaticCodeRef>,
    ) -> OSStatus;

    pub fn SecCodeCheckValidityWithErrors(
        code: SecCodeRef,
        flags: SecCSFlags,
        requirement: SecRequirementRef,
        errors: Option<&mut CFErrorRef>,
    ) -> OSStatus;

    pub fn SecStaticCodeCheckValidityWithErrors(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        requirement: SecRequirementRef,
        errors: Option<&mut CFErrorRef>,
    ) -> OSStatus;

    pub fn SecRequirementCreateWithStringAndErrors(
        text: CFStringRef,
        flags: SecCSFlags,
        errors: Option<&mut CFErrorRef>,
        requirement: Option<&mut SecRequirementRef>,
    ) -> OSStatus;

    pub fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        information: Option<&mut CFDictionaryRef>,
    ) -> OSStatus;

    pub fn CFErrorCopyUserInfo(err: CFErrorRef) -> CFDictionaryRef;

    pub fn SecCertificateCopyData(certificate: SecCertificateRef) -> CFDataRef;

    pub fn SecCertificateCopyValues(
        certificate: SecCertificateRef,
        keys: CFArrayRef,
        errors: Option<&mut CFErrorRef>,
    ) -> CFDictionaryRef;

    pub static kSecGuestAttributePid: CFStringRef;
    pub static kSecCodeInfoCertificates: CFStringRef;

    pub static kSecPropertyKeyValue: CFStringRef;
    pub static kSecPropertyKeyLabel: CFStringRef;
    pub static kSecPropertyKeyType: CFStringRef;

    pub static kSecOIDX509V1SubjectName: CFStringRef;
    pub static kSecOIDX509V1IssuerName: CFStringRef;
    pub static kSecOIDX509V1SerialNumber: CFStringRef;

    pub static kSecOIDCountryName: CFStringRef;
    pub static kSecOIDCommonName: CFStringRef;
    pub static kSecOIDOrganizationalUnitName: CFStringRef;
    pub static kSecOIDOrganizationName: CFStringRef;
}
