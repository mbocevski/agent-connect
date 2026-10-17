//! Python bindings for `agentconnect-core`, exposed as `agentconnect_core._native`.

use pyo3::prelude::*;

#[pymodule]
#[pyo3(name = "_native")]
mod native {
    use pyo3::prelude::*;

    #[pymodule_export]
    const PROTOCOL_VERSION: u32 = agentconnect_core::PROTOCOL_VERSION;

    #[pymodule_export]
    const CIPHERSUITE_V0: &str = agentconnect_core::CIPHERSUITE_V0;

    /// Return True if `v` is a protocol version this build can speak.
    #[pyfunction]
    fn supports_protocol(v: u32) -> bool {
        agentconnect_core::supports_protocol(v)
    }
}
