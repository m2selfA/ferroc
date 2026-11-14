// Test-only permission fault and mandatory exact descriptor restoration.
pub(super) fn test_world_read_then_restore(
    path: &Path,
    file: &File,
    action: impl FnOnce(),
) -> Result<()> {
    let user = User::current()?;
    let path = path16(path)?;
    let mut original = null_mut();
    // SAFETY: capture full original owner/DACL from the retained test file/dir
    // handle, not a reconstructed descriptor that might alter inheritance.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            1,
            5,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut original,
        )
    };
    let baseline = Local(original);
    ensure!(
        status == 0 && !baseline.0.is_null(),
        "test baseline ACL query failed"
    );
    let s = format!(
        "O:{}D:P(A;OICI;FA;;;{})(A;OICI;FR;;;WD)",
        user.text, user.text
    );
    let text: Vec<u16> = s.encode_utf16().chain(Some(0)).collect();
    let mut raw = null_mut();
    // SAFETY: test-owned descriptor with extra Everyone read ACE, bounded string.
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                null_mut(),
            )
        } != 0,
        "test descriptor failed"
    );
    let changed = Local(raw);
    struct Restore {
        path: Vec<u16>,
        sd: Local,
        done: bool,
    }
    impl Restore {
        fn restore(&mut self) -> Result<()> {
            // SAFETY: original SD remains live, ACL-only restore on owned test path.
            ensure!(
                unsafe { SetFileSecurityW(self.path.as_ptr(), 0x8000_0005, self.sd.0) } != 0,
                "test ACL restoration failed"
            );
            self.done = true;
            Ok(())
        }
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            if !self.done {
                let _ = self.restore();
            }
        }
    }
    let mut guard = Restore {
        path,
        sd: baseline,
        done: false,
    };
    // SAFETY: explicit test-only mutation, own path, no global policy/registry.
    ensure!(
        unsafe { SetFileSecurityW(guard.path.as_ptr(), 0x8000_0005, changed.0) } != 0,
        "test ACL change failed"
    );
    action();
    guard.restore()?;
    check_security(file)?;
    Ok(())
}
