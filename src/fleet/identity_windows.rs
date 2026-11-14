//! Narrow Windows FFI: CurrentUser DPAPI and current-process-user-only file ACL.
//! Same-user/administrator compromise, trusted-parent races and rollback are not
//! defeated. No shell, account creation, UI prompts, machine-wide or fallback.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::c_void,
    fs::File,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr::{null, null_mut},
};
use zeroize::{Zeroize, Zeroizing};
#[repr(C)]
struct Blob {
    len: u32,
    data: *mut u8,
}
#[repr(C)]
struct SecurityAttributes {
    len: u32,
    descriptor: *mut c_void,
    inherit: i32,
}
#[repr(C)]
struct SidAttributes {
    sid: *mut c_void,
    attributes: u32,
}
#[repr(C)]
struct TokenUser {
    user: SidAttributes,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Acl {
    revision: u8,
    pad: u8,
    size: u16,
    count: u16,
    pad2: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Ace {
    kind: u8,
    flags: u8,
    size: u16,
}
#[repr(C)]
#[derive(Default)]
struct FileInfo {
    attributes: u32,
    created: [u32; 2],
    accessed: [u32; 2],
    written: [u32; 2],
    volume: u32,
    size_hi: u32,
    size_lo: u32,
    links: u32,
    index_hi: u32,
    index_lo: u32,
}
#[link(name = "crypt32")]
unsafe extern "system" {
    fn CryptProtectData(
        input: *const Blob,
        description: *const u16,
        entropy: *const Blob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        output: *mut Blob,
    ) -> i32;
    fn CryptUnprotectData(
        input: *const Blob,
        description: *mut *mut u16,
        entropy: *const Blob,
        reserved: *mut c_void,
        prompt: *mut c_void,
        flags: u32,
        output: *mut Blob,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn OpenThreadToken(
        thread: *mut c_void,
        access: u32,
        as_self: i32,
        token: *mut *mut c_void,
    ) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        info: *mut c_void,
        len: u32,
        returned: *mut u32,
    ) -> i32;
    fn IsValidSid(sid: *const c_void) -> i32;
    fn GetLengthSid(sid: *const c_void) -> u32;
    fn EqualSid(a: *const c_void, b: *const c_void) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn GetSecurityInfo(
        handle: *mut c_void,
        kind: u32,
        info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn IsValidAcl(acl: *const c_void) -> i32;
    fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> i32;
    #[cfg(test)]
    fn SetFileSecurityW(path: *const u16, info: u32, descriptor: *const c_void) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetCurrentThread() -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn CreateDirectoryW(path: *const u16, security: *const SecurityAttributes) -> i32;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *const SecurityAttributes,
        creation: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    fn GetFileInformationByHandle(handle: *mut c_void, info: *mut FileInfo) -> i32;
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocations returned by documented LocalAlloc-family APIs, owned once.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
struct Handle(*mut c_void);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: successfully opened token handle, owned once (not pseudo handle).
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct DpapiOutput(Blob);
impl Drop for DpapiOutput {
    fn drop(&mut self) {
        if !self.0.data.is_null() {
            // SAFETY: DPAPI output owns exactly len bytes until LocalFree.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.data, self.0.len as usize).zeroize();
                LocalFree(self.0.data.cast());
            }
        }
    }
}
fn os_error() -> anyhow::Error {
    std::io::Error::last_os_error().into()
}
fn no_impersonation() -> Result<()> {
    let mut token = null_mut();
    // SAFETY: pseudo current-thread handle, live output pointer, TOKEN_QUERY=8.
    if unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token) } != 0 {
        let _owned = Handle(token);
        anyhow::bail!("impersonated identity persistence unsupported");
    }
    ensure!(
        std::io::Error::last_os_error().raw_os_error() == Some(1008),
        "unable to rule out thread impersonation"
    );
    Ok(())
}
struct User {
    sid: Vec<u8>,
    text: String,
}
impl User {
    fn current() -> Result<Self> {
        no_impersonation()?;
        let mut token = null_mut();
        // SAFETY: current process pseudo handle and valid token output.
        ensure!(
            unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } != 0,
            "query process token failed"
        );
        let token = Handle(token);
        let mut size = 0;
        // SAFETY: documented size query with null output and zero length.
        unsafe {
            GetTokenInformation(token.0, 1, null_mut(), 0, &mut size);
        }
        ensure!(
            (std::mem::size_of::<TokenUser>()..=65536).contains(&(size as usize)),
            "invalid token user size"
        );
        let mut bytes = vec![0u8; size as usize];
        // SAFETY: buffer sized by prior query, TOKEN_USER=1, API retains no pointer.
        ensure!(
            unsafe { GetTokenInformation(token.0, 1, bytes.as_mut_ptr().cast(), size, &mut size) }
                != 0,
            "read process user failed"
        );
        // SAFETY: successful TOKEN_USER query provides struct; read_unaligned does not assume Vec<u8> alignment.
        let raw = unsafe { bytes.as_ptr().cast::<TokenUser>().read_unaligned() };
        // SAFETY: SID pointer refers to live token buffer and validated by OS.
        ensure!(
            !raw.user.sid.is_null() && unsafe { IsValidSid(raw.user.sid) } != 0,
            "invalid process SID"
        );
        let len = unsafe { GetLengthSid(raw.user.sid) } as usize;
        ensure!((8..=68).contains(&len), "invalid process SID length");
        let start = raw.user.sid as usize;
        let base = bytes.as_ptr() as usize;
        ensure!(
            start >= base
                && start
                    .checked_add(len)
                    .is_some_and(|end| end <= base + bytes.len()),
            "token SID outside buffer"
        );
        // SAFETY: above bounds establish live SID range, copied before token buffer drops.
        let sid = unsafe { std::slice::from_raw_parts(raw.user.sid.cast::<u8>(), len) }.to_vec();
        let mut text = null_mut();
        // SAFETY: live valid SID and an owned LocalAlloc string result.
        ensure!(
            unsafe { ConvertSidToStringSidW(raw.user.sid, &mut text) } != 0,
            "SID string conversion failed"
        );
        let owned = Local(text.cast());
        let mut count = 0;
        // SAFETY: OS emits a NUL-terminated SID string, bounded legal SID text (<256 UTF16 units).
        while count < 256 && unsafe { *text.add(count) } != 0 {
            count += 1;
        }
        ensure!(count < 256, "oversized SID text");
        let text = String::from_utf16(unsafe { std::slice::from_raw_parts(text, count) })?;
        drop(owned);
        Ok(Self { sid, text })
    }
    fn descriptor(&self, directory: bool) -> Result<Local> {
        let s = format!(
            "O:{}D:P(A;{};FA;;;{})",
            self.text,
            if directory { "OICI" } else { "" },
            self.text
        );
        let text: Vec<u16> = s.encode_utf16().chain(Some(0)).collect();
        let mut sd = null_mut();
        // SAFETY: terminated UTF16 string, revision1, output owned by LocalFree.
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut sd,
                    null_mut(),
                )
            } != 0,
            "private security descriptor creation failed"
        );
        Ok(Local(sd))
    }
}
fn path16(path: &Path) -> Result<Vec<u16>> {
    let mut text: Vec<u16> = path.as_os_str().encode_wide().collect();
    ensure!(!text.contains(&0), "NUL in identity path");
    text.push(0);
    Ok(text)
}
pub(super) fn create_directory(path: &Path) -> Result<()> {
    let user = User::current()?;
    let sd = user.descriptor(true)?;
    let attributes = SecurityAttributes {
        len: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: sd.0,
        inherit: 0,
    };
    let path = path16(path)?;
    // SAFETY: path and descriptor remain live throughout synchronous creation.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(os_error());
    }
    Ok(())
}
pub(super) fn create_file(path: &Path) -> Result<File> {
    create_with_access(path, 0xC000_0000)
}
// Only fresh allocated stages need DELETE for a future same-handle rename.
pub(super) fn create_stage_file(path: &Path) -> Result<File> {
    create_with_access(path, 0xC001_0000)
}
fn create_with_access(path: &Path, access: u32) -> Result<File> {
    let user = User::current()?;
    let sd = user.descriptor(false)?;
    let attributes = SecurityAttributes {
        len: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: sd.0,
        inherit: 0,
    };
    let path = path16(path)?;
    // SAFETY: CREATE_NEW=1 never opens/replaces existing path, GENERIC_READ|WRITE,
    // share read+write but not delete, regular file with reparse-point open flag.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            3,
            &attributes,
            1,
            0x0020_0080,
            null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(os_error());
    }
    // SAFETY: successful exclusive-create handle ownership moves to File once.
    Ok(unsafe { File::from_raw_handle(handle) })
}
pub(super) fn check_security(file: &File) -> Result<()> {
    let user = User::current()?;
    let (mut owner, mut acl, mut sd) = (null_mut(), null_mut(), null_mut());
    // SAFETY: handle retained by File; OWNER|DACL=5, SE_FILE_OBJECT=1, descriptor
    // keeps returned owner/ACL pointers alive until LocalFree after validation.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            1,
            5,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut sd,
        )
    };
    let _sd = Local(sd);
    ensure!(
        status == 0,
        "query private file owner/DACL failed ({status})"
    );
    ensure!(
        !owner.is_null() && !acl.is_null(),
        "missing private owner/DACL"
    );
    // SAFETY: live OS security descriptor; copied current-user SID remains live.
    ensure!(
        unsafe { EqualSid(owner, user.sid.as_ptr().cast()) } != 0
            && unsafe { IsValidAcl(acl) } != 0,
        "wrong identity file owner or invalid ACL"
    );
    let header = unsafe { acl.cast::<Acl>().read_unaligned() };
    ensure!(
        header.count == 1,
        "private identity DACL must contain only one user ACE"
    );
    let mut ace = null_mut();
    ensure!(
        unsafe { GetAce(acl, 0, &mut ace) } != 0 && !ace.is_null(),
        "private ACE unavailable"
    );
    let header = unsafe { ace.cast::<Ace>().read_unaligned() };
    ensure!(
        header.kind == 0 && header.flags & 8 == 0 && header.size as usize >= 8 + user.sid.len(),
        "unexpected private ACE kind/flags/length"
    );
    let mask = unsafe { ace.cast::<u8>().add(4).cast::<u32>().read_unaligned() };
    let sid = unsafe { ace.cast::<u8>().add(8) };
    ensure!(
        mask & 0x001f_01ff == 0x001f_01ff
            && unsafe { EqualSid(sid.cast(), user.sid.as_ptr().cast()) } != 0,
        "identity ACE must grant full access only to current user"
    );
    Ok(())
}
pub(super) fn single_link_file_id(file: &File) -> Result<String> {
    let mut info = FileInfo::default();
    // SAFETY: File owns a live handle and info has the exact ABI layout above.
    ensure!(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
        "query fence file identity failed"
    );
    ensure!(
        info.links == 1,
        "fence database/marker must have exactly one link"
    );
    Ok(format!(
        "win-{:08x}-{:08x}{:08x}",
        info.volume, info.index_hi, info.index_lo
    ))
}

pub(super) fn directory_file_id(file: &File) -> Result<String> {
    let mut info = FileInfo::default();
    // SAFETY: live retained directory handle and exact ABI FileInfo layout.
    ensure!(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
        "query allocation directory identity failed"
    );
    ensure!(
        info.attributes & 0x10 != 0 && info.attributes & 0x400 == 0,
        "allocation object is not a plain directory"
    );
    Ok(format!(
        "win-{:08x}-{:08x}{:08x}",
        info.volume, info.index_hi, info.index_lo
    ))
}
pub(super) fn same_file(a: &File, b: &File) -> Result<()> {
    let mut left = FileInfo::default();
    let mut right = FileInfo::default();
    // SAFETY: valid retained handles and exactly sized BY_HANDLE_FILE_INFORMATION.
    ensure!(
        unsafe { GetFileInformationByHandle(a.as_raw_handle(), &mut left) } != 0
            && unsafe { GetFileInformationByHandle(b.as_raw_handle(), &mut right) } != 0,
        "query identity directory file ID failed"
    );
    ensure!(
        (left.volume, left.index_hi, left.index_lo)
            == (right.volume, right.index_hi, right.index_lo),
        "identity directory replaced"
    );
    Ok(())
}
fn dpapi(context: &[u8], bytes: &[u8], encrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    no_impersonation()?;
    ensure!(
        bytes.len() <= 16384 && context.len() <= 4096,
        "DPAPI input bound exceeded"
    );
    let input = Blob {
        len: bytes.len() as u32,
        data: bytes.as_ptr().cast_mut(),
    };
    let entropy = Blob {
        len: context.len() as u32,
        data: context.as_ptr().cast_mut(),
    };
    let mut output = DpapiOutput(Blob {
        len: 0,
        data: null_mut(),
    });
    // SAFETY: borrowed input/entropy buffers are read-only documented [in], live
    // for synchronous API; no prompt, no reserved pointer, UI_FORBIDDEN=1 only
    // (never LOCAL_MACHINE=4). Description output NULL avoids another allocation.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                null(),
                &entropy,
                null_mut(),
                null_mut(),
                1,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &input,
                null_mut(),
                &entropy,
                null_mut(),
                null_mut(),
                1,
                &mut output.0,
            )
        }
    };
    ensure!(ok != 0, "CurrentUser DPAPI operation failed");
    ensure!(
        !output.0.data.is_null() && output.0.len <= 16384,
        "invalid DPAPI output size"
    );
    // SAFETY: DPAPI successful output owns this range. Owned memory is wiped and
    // freed when output drops; copied plaintext is separately Zeroizing.
    Ok(Zeroizing::new(
        unsafe { std::slice::from_raw_parts(output.0.data, output.0.len as usize) }.to_vec(),
    ))
}
#[cfg(test)]
include!("identity_acl_tests.inc.rs");

pub(super) fn protect(context: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    dpapi(context, bytes, true)
}
pub(super) fn unprotect(context: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    dpapi(context, bytes, false)
        .context("protected identity cannot be opened; no regeneration/fallback")
}
