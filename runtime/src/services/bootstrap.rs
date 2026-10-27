use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use super::system_service::SystemService;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ServiceName(pub String);

impl From<&str> for ServiceName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for ServiceName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

pub struct BootstrapNamespace {
    ports: Mutex<HashMap<ServiceName, u32>>,
    services: Mutex<HashMap<ServiceName, Arc<dyn SystemService>>>,
}

impl Default for BootstrapNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl BootstrapNamespace {
    pub fn new() -> Self {
        Self {
            ports: Mutex::new(HashMap::new()),
            services: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_service(&self, service: Arc<dyn SystemService>) {
        let name = ServiceName::from(service.name());
        self.services.lock().unwrap().insert(name, service);
    }

    pub fn bootstrap_register(&self, name: ServiceName, port: u32) {
        self.ports.lock().unwrap().insert(name, port);
    }

    pub fn bootstrap_look_up(&self, name: &ServiceName) -> Option<u32> {
        self.ports.lock().unwrap().get(name).copied()
    }

    pub fn get_service(&self, name: &ServiceName) -> Option<Arc<dyn SystemService>> {
        self.services.lock().unwrap().get(name).cloned()
    }

    pub fn is_registered(&self, name_str: &str) -> bool {
        let name = ServiceName::from(name_str);
        self.services.lock().unwrap().contains_key(&name) || self.ports.lock().unwrap().contains_key(&name)
    }
}
