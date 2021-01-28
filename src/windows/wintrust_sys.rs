pub use winapi::shared::minwindef::{BOOL, DWORD};
pub use winapi::shared::ntdef::HANDLE;
pub use winapi::um::handleapi::INVALID_HANDLE_VALUE;
pub use winapi::um::softpub::WINTRUST_ACTION_GENERIC_VERIFY_V2;
pub use winapi::um::wincrypt::*;
pub use winapi::um::wintrust::*;

#[link(name = "Wintrust")]
extern "system" {
    pub fn WTHelperProvDataFromStateData(handle: HANDLE) -> *const std::ffi::c_void;

    pub fn WTHelperGetProvSignerFromChain(
        pProvData: *const std::ffi::c_void,
        idxSigner: DWORD,
        fCounterSigner: BOOL,
        idxCounterSigner: DWORD,
    ) -> *const std::ffi::c_void;

    pub fn WTHelperGetProvCertFromChain(
        pSgnr: *const std::ffi::c_void,
        idxCert: DWORD,
    ) -> *const std::ffi::c_void;
}
