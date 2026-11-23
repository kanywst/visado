//! Capturing the audit records a gate writes. Each test binary that uses
//! this holds one test: a scoped tracing subscriber does not see events
//! reliably while other tests run on other threads.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use serde_json::Value;
use visado_extauthz::audit::AuditRecord;

/// The JSON log lines written while a [`Capture`] was in scope.
#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl Logs {
    /// Everything written so far.
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    /// The `visado::audit` events written so far.
    pub fn audit_events(&self) -> Vec<Value> {
        self.text()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|e| e["target"] == "visado::audit")
            .collect()
    }

    /// The audit records written so far.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.audit_events()
            .into_iter()
            .map(|e| serde_json::from_value(e["fields"].clone()).unwrap())
            .collect()
    }
}

/// Sends this thread's JSON log lines to [`Logs`] until dropped.
pub struct Capture {
    pub logs: Logs,
    _guard: tracing::subscriber::DefaultGuard,
}

impl Capture {
    #[must_use]
    pub fn start() -> Self {
        let logs = Logs::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        Self {
            _guard: tracing::subscriber::set_default(subscriber),
            logs,
        }
    }
}
