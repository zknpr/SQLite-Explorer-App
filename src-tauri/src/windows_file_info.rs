//! Descriptor-based file identity for native connections and WASM snapshots.
//! The mapping from the system's answers to an identity is a plain function, so
//! the unit tests run it on every platform.
use std::io;
#[cfg(windows)]
use std::{fs::File, mem::size_of, os::windows::io::AsRawHandle};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx, BY_HANDLE_FILE_INFORMATION,
    FILE_BASIC_INFO, FILE_ID_INFO,
};

#[cfg(windows)]
pub(crate) fn identity(file: &File) -> Result<(u64, u128), String> {
    let mut info = FILE_ID_INFO::default();
    // The live File owns the handle; the buffer and size match FileIdInfo.
    // Use all 128 bits: a 64-bit file index is not unique on ReFS.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    let id_info = if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((info.VolumeSerialNumber, info.FileId.Identifier))
    };
    identity_from(id_info, || {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // Same handle ownership; the buffer is the struct the call fills.
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow))
    })
}

/// ERROR_INVALID_PARAMETER: FileIdInfo's answer on a volume with no file ids of its
/// own, FAT32 and exFAT (measured on Windows 11).
const ERROR_INVALID_PARAMETER_CODE: i32 = 87;
#[cfg(windows)]
const _: () = assert!(ERROR_INVALID_PARAMETER_CODE as u32 == windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER);

/// A file's identity from FileIdInfo's answer (`id_info`: the 64-bit volume serial and
/// the 128-bit file id), or, where that is ERROR_INVALID_PARAMETER and only then, from
/// GetFileInformationByHandle's (`by_handle`: the 32-bit volume serial and the file
/// index's high and low halves). Which form a file gets depends only on its volume, so
/// two identities of one file are always the same form.
///
/// FAT32 and exFAT answer only the second, and there the index is not a file's own:
/// it is made from the containing folder's first cluster and the byte offset of the
/// file's entry in it (BY_HANDLE_FILE_INFORMATION, Remarks). It stays the same across
/// an in-place write, and a rename that replaces the file changes it (measured on
/// Windows 11). But a file created after a delete can take the freed entry and so the
/// same index, a rename to a longer name can move the entry and change it, and some
/// defragmenters change it too. For the native lane that leaves a false
/// ERR_NATIVE_FILE_CHANGED at worst: SQLite opens the database sharing read and write
/// but not delete (os_win.c, winOpen), so while the sidecar holds it the file cannot
/// be deleted, renamed or replaced, which is what a reused index would hide (read from
/// the source, not measured). The WebAssembly lane holds nothing; see
/// `WasmGeneration`.
fn identity_from(
    id_info: io::Result<(u64, [u8; 16])>,
    by_handle: impl FnOnce() -> io::Result<(u32, u32, u32)>,
) -> Result<(u64, u128), String> {
    let (volume, id) = match id_info {
        Ok((volume, id)) => (volume, u128::from_le_bytes(id)),
        Err(e) if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER_CODE) => {
            let (serial, high, low) = by_handle().map_err(|e| format!("cannot read file identity: {e}"))?;
            (u64::from(serial), (u128::from(high) << 32) | u128::from(low))
        }
        Err(e) => return Err(format!("cannot read file identity: {e}")),
    };
    if id == 0 {
        return Err("filesystem did not provide a file identity".into());
    }
    Ok((volume, id))
}

/// The final component of `path`'s long name, as GetLongPathNameW gives it (an 8.3
/// short name such as "XDB-WA~1" comes back as "x.db-wal"), or `None` when nothing
/// is at `path`.
#[cfg(windows)]
pub(crate) fn long_name(path: &std::path::Path) -> io::Result<Option<std::ffi::OsString>> {
    wide_path_call(path, |from, to, len| unsafe { windows_sys::Win32::Storage::FileSystem::GetLongPathNameW(from, to, len) })
}

/// The final component of `path`'s 8.3 short name (GetShortPathNameW): the same as its
/// long name on a volume that does not make short names.
#[cfg(all(windows, test))]
pub(crate) fn short_name(path: &std::path::Path) -> io::Result<Option<std::ffi::OsString>> {
    wide_path_call(path, |from, to, len| unsafe { windows_sys::Win32::Storage::FileSystem::GetShortPathNameW(from, to, len) })
}

/// Calls a path-to-path Win32 function with a buffer it may ask to grow, and gives
/// back the final component of what it wrote; `None` for NotFound. The path is
/// handed over absolute and verbatim (`verbatim`), so one past MAX_PATH works.
#[cfg(windows)]
fn wide_path_call(
    path: &std::path::Path,
    call: impl Fn(*const u16, *mut u16, u32) -> u32,
) -> io::Result<Option<std::ffi::OsString>> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    let absolute = std::path::absolute(path)?;
    let from: Vec<u16> = verbatim(absolute.as_os_str()).encode_wide().chain(Some(0)).collect();
    let mut to = vec![0u16; 260];
    loop {
        // The buffer and its length go together; the input is NUL-terminated.
        let written = call(from.as_ptr(), to.as_mut_ptr(), to.len() as u32) as usize;
        if written == 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound { Ok(None) } else { Err(error) };
        }
        if written < to.len() {
            to.truncate(written);
            let full = std::path::PathBuf::from(std::ffi::OsString::from_wide(&to));
            return Ok(full.file_name().map(|name| name.to_os_string()));
        }
        to.resize(written, 0);
    }
}

/// An absolute path in the verbatim form Win32 takes past MAX_PATH (260 characters):
/// "\\?\C:\…" for a drive path, "\\?\UNC\server\share\…" for a UNC path. A path
/// already verbatim, or a device path ("\\.\"), is left as it is. The app does not
/// declare itself long-path aware, so a plain path over the limit makes the call fail.
#[cfg(any(windows, test))]
fn verbatim(path: &std::ffi::OsStr) -> std::ffi::OsString {
    let bytes = path.as_encoded_bytes();
    if bytes.starts_with(br"\\?\") || bytes.starts_with(br"\\.\") {
        return path.to_os_string();
    }
    let mut out = std::ffi::OsString::new();
    match bytes.strip_prefix(br"\\") {
        Some(rest) => {
            out.push(r"\\?\UNC\");
            // SAFETY: only the two ASCII backslashes were cut from the front, which is
            // where an OsStr's encoded bytes may be split.
            out.push(unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(rest) });
        }
        None => {
            out.push(r"\\?\");
            out.push(path);
        }
    }
    out
}

#[cfg(windows)]
pub(crate) fn change_time(file: &File) -> Result<i64, String> {
    let mut info = FILE_BASIC_INFO::default();
    // Same descriptor ownership and correctly sized output buffer as above.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileBasicInfo,
            (&mut info as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(format!(
            "cannot read file change time: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(info.ChangeTime)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run on every platform; `a_destination_past_max_path_is_judged_by_its_long_name_on_windows`
    /// (native.rs) is the effect on Windows.
    #[test]
    fn a_path_is_made_verbatim_for_win32_past_max_path() {
        use std::ffi::{OsStr, OsString};
        for (path, wanted) in [
            (r"C:\data\x.db", r"\\?\C:\data\x.db"),
            (r"\\server\share\x.db", r"\\?\UNC\server\share\x.db"),
            (r"\\?\C:\data\x.db", r"\\?\C:\data\x.db"),
            (r"\\?\UNC\server\share\x.db", r"\\?\UNC\server\share\x.db"),
            (r"\\.\COM1", r"\\.\COM1"),
        ] {
            assert_eq!(verbatim(OsStr::new(path)), OsString::from(wanted), "{path}");
        }
    }

    /// FAT32 and exFAT answer FileIdInfo with ERROR_INVALID_PARAMETER; the handle
    /// information still carries the volume serial and the 64-bit file index
    /// (the figures below are the ones measured on a FAT32 volume).
    #[test]
    fn a_volume_without_file_id_info_is_identified_from_the_handle_information() {
        let invalid = || io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER_CODE);
        assert_eq!(identity_from(Err(invalid()), || Ok((0x5e1d_6f29, 0, 0x0040_00e0))), Ok((0x5e1d_6f29, 0x0040_00e0)));
        assert_eq!(identity_from(Err(invalid()), || Ok((7, 1, 2))), Ok((7, (1 << 32) | 2)));
        // A volume that answers FileIdInfo is identified by it, in all 128 bits,
        // and the handle information is never asked for.
        let mut id = [0u8; 16];
        id[0] = 0xe0;
        id[15] = 0x01;
        assert_eq!(
            identity_from(Ok((0x0000_0001_5c22_3750, id)), || panic!("not asked")),
            Ok((0x0000_0001_5c22_3750, u128::from_le_bytes(id)))
        );
        // Any other FileIdInfo failure stays one (ERROR_ACCESS_DENIED), as does
        // a failed fallback (ERROR_INVALID_HANDLE).
        assert!(identity_from(Err(io::Error::from_raw_os_error(5)), || panic!("not asked")).is_err());
        assert!(identity_from(Err(invalid()), || Err(io::Error::from_raw_os_error(6))).is_err());
        // A zero id is no identity, in either form.
        assert!(identity_from(Ok((1, [0; 16])), || panic!("not asked")).is_err());
        assert!(identity_from(Err(invalid()), || Ok((1, 0, 0))).is_err());
    }
}
