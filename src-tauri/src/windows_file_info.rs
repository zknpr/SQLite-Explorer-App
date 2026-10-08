//! Descriptor-based file identity for native connections and WASM snapshots.
use std::{fs::File, io, mem::size_of, os::windows::io::AsRawHandle};
use windows_sys::Win32::Storage::FileSystem::{
    FileBasicInfo, FileIdInfo, GetFileInformationByHandleEx, FILE_BASIC_INFO, FILE_ID_INFO,
};

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
    if ok == 0 {
        return Err(format!(
            "cannot read file identity: {}",
            io::Error::last_os_error()
        ));
    }
    let id = u128::from_le_bytes(info.FileId.Identifier);
    if id == 0 {
        return Err("filesystem did not provide a file identity".into());
    }
    Ok((info.VolumeSerialNumber, id))
}

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
