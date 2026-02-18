use std::collections::HashMap;

pub struct AppState {
    store: HashMap<String, String>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            store: HashMap::new(),
        }
    }

    pub fn execute(&mut self, operation: &[u8]) -> Vec<u8> {
        let op_str = String::from_utf8_lossy(operation);

        if let Some(put) = op_str.strip_prefix("PUT:") {
            let parts: Vec<&str> = put.split(':').collect();
            if parts.len() == 2 {
                self.store
                    .insert(parts[0].to_string(), parts[1].to_string());
                return b"OK".to_vec();
            }
        } else if let Some(key) = op_str.strip_prefix("GET:") {
            if let Some(value) = self.store.get(key) {
                return value.as_bytes().to_vec();
            }
            return b"NOT_FOUND".to_vec();
        }

        return b"INVALID_OPERATION".to_vec();
    }
}
