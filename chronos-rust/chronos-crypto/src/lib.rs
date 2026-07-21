pub mod fhe;
pub mod snark;
pub mod vdf;
pub mod posw;

use pyo3::prelude::*;

#[pymodule]
fn fast_posw(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(posw::compute_posw_chain, m)?)?;
    Ok(())
}
