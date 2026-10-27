pub mod decoder;
pub mod encoder;
pub mod interfaces;
pub mod message;
pub mod registry;

pub use decoder::MigDecoder;
pub use encoder::MigEncoder;
pub use message::{MachMessage, MigReply, NDR};
pub use registry::{MigRegistry, MigSubsystem};

use std::sync::Arc;

pub fn default_registry() -> MigRegistry {
    let mut reg = MigRegistry::new();
    reg.register(Arc::new(interfaces::host::HostSubsystem));
    reg.register(Arc::new(interfaces::task::TaskSubsystem));
    reg.register(Arc::new(interfaces::vm::VmSubsystem));
    reg.register(Arc::new(interfaces::port::PortSubsystem));
    reg.register(Arc::new(interfaces::iokit::IOKitSubsystem));
    reg.register(Arc::new(interfaces::clock::ClockSubsystem));
    reg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_registers_and_dispatches_subsystems() {
        let registry = default_registry();
        assert_eq!(registry.count(), 6);
    }
}
