pub mod backboard_hid;
pub mod bootstrap;
pub mod cfprefsd;
pub mod notification_center;
pub mod runningboard;
pub mod system_service;

pub use backboard_hid::BackBoardHidService;
pub use bootstrap::{BootstrapNamespace, ServiceName};
pub use cfprefsd::CfprefsdService;
pub use notification_center::NotificationCenterService;
pub use runningboard::RunningBoardService;
pub use system_service::{SystemService, XpcMessage};

use std::sync::Arc;

pub fn default_bootstrap() -> BootstrapNamespace {
    let bs = BootstrapNamespace::new();
    bs.register_service(Arc::new(NotificationCenterService));
    bs.register_service(Arc::new(RunningBoardService));
    bs.register_service(Arc::new(CfprefsdService));
    bs.register_service(Arc::new(BackBoardHidService));
    bs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bootstrap_registers_standard_services() {
        let bs = default_bootstrap();
        assert!(bs.is_registered("com.apple.system.notification_center"));
        assert!(bs.is_registered("com.apple.runningboard"));
        assert!(bs.is_registered("com.apple.cfprefsd.daemon"));
        assert!(!bs.is_registered("com.apple.unknown.service"));
    }
}
