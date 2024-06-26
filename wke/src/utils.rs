use windows::{
    core::*, Win32::Foundation::*, Win32::Storage::FileSystem::*, Win32::System::ProcessStatus::*,
    Win32::System::SystemServices::*,
};

pub trait Primitives {
    fn new() -> Self;
}

#[derive(Copy, Clone)]
pub struct HEVDPrimitives {
    pub driver_handle: HANDLE,
    pub stack_buffer_overflow_ioctl: u32,
    pub type_confusion_ioctl: u32,
    pub allocate_uaf_ioctl: u32,
    pub free_uaf_ioctl: u32,
    pub use_uaf_ioctl: u32,
    pub fake_object_ioctl: u32,
    pub uninitialized_heap_variable_ioctl: u32,
    pub uninitialized_stack_variable_ioctl: u32,
    pub non_paged_pool_overflow_nx_ioctl: u32,
}

impl Primitives for HEVDPrimitives {
    fn new() -> HEVDPrimitives {
        let driver_handle = crate::utils::open_device("\\\\.\\HackSysExtremeVulnerableDriver\0");

        if driver_handle.is_err() {
            HEVDPrimitives {
                driver_handle: HANDLE(0),
                stack_buffer_overflow_ioctl: 0x222003,
                type_confusion_ioctl: 0x222023,
                allocate_uaf_ioctl: 0x222013,
                free_uaf_ioctl: 0x22201B,
                use_uaf_ioctl: 0x222017,
                fake_object_ioctl: 0x22201F,
                uninitialized_heap_variable_ioctl: 0x222033,
                uninitialized_stack_variable_ioctl: 0x22202f,
                non_paged_pool_overflow_nx_ioctl: 0x22204b,
            };
        }

        HEVDPrimitives {
            driver_handle: driver_handle.unwrap(),
            stack_buffer_overflow_ioctl: 0x222003,
            type_confusion_ioctl: 0x222023,
            allocate_uaf_ioctl: 0x222013,
            free_uaf_ioctl: 0x22201B,
            use_uaf_ioctl: 0x222017,
            fake_object_ioctl: 0x22201F,
            uninitialized_heap_variable_ioctl: 0x222033,
            uninitialized_stack_variable_ioctl: 0x22202f,
            non_paged_pool_overflow_nx_ioctl: 0x22204b,
        }
    }
}

pub fn open_device(device_name: &str) -> Result<HANDLE> {
    let driver_string: Vec<u16> = device_name.encode_utf16().collect();

    unsafe {
        let driver_name: PCWSTR = PCWSTR(driver_string.as_ptr());
        let device = CreateFileW(
            driver_name,
            FILE_ACCESS_FLAGS(GENERIC_READ | GENERIC_WRITE),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        )
        .unwrap();

        if device == HANDLE(0) {}

        return Ok(device);
    };
}

pub fn lookup_base_address(module_name: &str) -> u64 {
    let mut drivers_base: Vec<usize> = Vec::with_capacity(2048);
    let mut n_drivers = drivers_base.capacity() as u32;
    let success;

    unsafe {
        drivers_base.set_len(n_drivers as usize);
    }

    unsafe {
        success = K32EnumDeviceDrivers(
            drivers_base.as_ptr() as *mut *mut std::os::raw::c_void,
            1024,
            &mut n_drivers,
        )
        .as_bool();
    }
    if !success {
        return 0;
    }

    for base_address in drivers_base {
        if base_address == 0 {
            continue;
        }

        let mut base_name: [u8; 1024] = [0; 1024];
        let driver_base_name;
        unsafe {
            driver_base_name = K32GetDeviceDriverBaseNameA(
                base_address as *mut std::os::raw::c_void,
                &mut base_name,
            );
        }
        if driver_base_name == 0 {
            continue;
        }

        let idx_zero = match base_name.iter().position(|&x| x == 0) {
            Some(v) => v,
            None => base_name.len(),
        };
        let cname = match std::str::from_utf8(&base_name[..idx_zero]) {
            Ok(v) => v,
            Err(_e) => {
                continue;
            }
        };

        if cname.to_lowercase() == module_name.to_string().to_lowercase()
            || cname
                .to_lowercase()
                .contains(module_name.to_string().to_lowercase().as_str())
        {
            return base_address as u64;
        }
    }

    return 0;
}
