//! Limine boot-protocol requests. These statics live in dedicated link
//! sections so the Limine bootloader can find and fill them in before we
//! take control.

use limine::modules::InternalModule;
use limine::request::{
    ExecutableAddressRequest, ExecutableCmdlineRequest, ExecutableFileRequest, FramebufferRequest,
    HhdmRequest, MemoryMapRequest, ModuleRequest, RequestsEndMarker, RequestsStartMarker,
    RsdpRequest, StackSizeRequest,
};
use limine::BaseRevision;

/// Ask Limine for a 64 KiB bootstrap stack. Comfortable for early init.
const STACK_SIZE: u64 = 64 * 1024;
const INTERNAL_INIT_MODULE: InternalModule =
    InternalModule::new().with_path(c"/boot/userspace_init.elf");
const INTERNAL_INIT_MODULES: [&InternalModule; 1] = [&INTERNAL_INIT_MODULE];

#[used]
#[link_section = ".limine_requests"]
pub static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
#[link_section = ".limine_requests"]
pub static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[link_section = ".limine_requests"]
pub static MEMMAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[link_section = ".limine_requests"]
pub static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[link_section = ".limine_requests"]
pub static STACK_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(STACK_SIZE);

#[used]
#[link_section = ".limine_requests"]
pub static KERNEL_ADDRESS_REQUEST: ExecutableAddressRequest = ExecutableAddressRequest::new();

#[used]
#[link_section = ".limine_requests"]
pub static KERNEL_FILE_REQUEST: ExecutableFileRequest = ExecutableFileRequest::new();

/// Kernel command-line string, passed by Limine from the bootloader
/// config. Parsed at boot for knobs like `writeback_secs=N`
/// (issue #555).
#[used]
#[link_section = ".limine_requests"]
pub static KERNEL_CMDLINE_REQUEST: ExecutableCmdlineRequest = ExecutableCmdlineRequest::new();

#[used]
#[link_section = ".limine_requests"]
pub static MODULE_REQUEST: ModuleRequest =
    ModuleRequest::new().with_internal_modules(&INTERNAL_INIT_MODULES);

#[used]
#[link_section = ".limine_requests"]
pub static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

#[used]
#[link_section = ".limine_requests_start"]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[link_section = ".limine_requests_end"]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();
