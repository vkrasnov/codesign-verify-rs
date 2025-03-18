#[allow(non_snake_case)]
mod context;
mod wintrust_sys;

use super::Error;
use wintrust_sys::*;

pub(crate) struct Verifier(Vec<u16>);
pub(crate) use context::Context;

impl Verifier {
    pub fn for_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        use std::os::windows::ffi::OsStrExt;

        let mut path_vec: Vec<u16> = path.as_ref().as_os_str().encode_wide().collect();
        path_vec.push(0); // Make sure path is null terminated

        Ok(Self(path_vec))
    }

    // Extract the path of a pid, then call for file
    pub fn for_pid(pid: i32) -> Result<Self, Error> {
        let path = get_process_path(pid as _).map_err(|e| Error::IoError(e))?;
        Self::for_file(path)
    }

    pub fn verify(&self) -> Result<Context, Error> {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as _,
            pcwszFilePath: self.0.as_ptr(),
            hFile: std::ptr::null_mut(),
            pgKnownSubject: std::ptr::null(),
        };

        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as _,
            pPolicyCallbackData: std::ptr::null_mut(),
            pSIPClientData: std::ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            u: Default::default(),
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: std::ptr::null_mut(),
            pwszURLReference: std::ptr::null_mut(),
            dwProvFlags: WTD_DISABLE_MD2_MD4
                | WTD_REVOCATION_CHECK_END_CERT
                | WTD_NO_IE4_CHAIN_FLAG
                | WTD_CACHE_ONLY_URL_RETRIEVAL,
            dwUIContext: WTD_UICONTEXT_EXECUTE,
            pSignatureSettings: std::ptr::null_mut(),
        };

        *unsafe { data.u.pFile_mut() } = &mut file_info;

        let mut guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // Verify that the signature is actually valid
        match unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE as _,
                &mut guid,
                &mut data as *mut _ as _,
            )
        } {
            0 => {}
            _ => {
                let err = std::io::Error::last_os_error();
                let _ = Context::new(data.hWVTStateData); // So close gets called on the data
                if err.raw_os_error() == Some(winapi::shared::winerror::TRUST_E_NOSIGNATURE) {
                    return Err(Error::Unsigned);
                } else {
                    return Err(Error::IoError(err));
                }
            }
        }

        Context::new(data.hWVTStateData)
    }
}

/// Attempts to get the full system path for a given proccess id
fn get_process_path(proc_id: u32) -> std::io::Result<String> {
    use winapi::shared::minwindef;
    use winapi::um::{processthreadsapi, winbase, winnt};

    let mut buf = [0u16; 2048];

    unsafe {
        let proc_handle = match processthreadsapi::OpenProcess(
            winnt::PROCESS_QUERY_LIMITED_INFORMATION,
            minwindef::FALSE,
            proc_id,
        ) {
            handle if handle.is_null() => return Err(std::io::Error::last_os_error()),
            handle => handle,
        };

        let mut path_len = buf.len() as _;

        match winbase::QueryFullProcessImageNameW(proc_handle, 0, buf.as_mut_ptr(), &mut path_len) {
            0 => Err(std::io::Error::last_os_error()),
            _ => Ok(String::from_utf16_lossy(&buf[..path_len as usize])),
        }
    }
}
