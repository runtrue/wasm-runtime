//! Convert a WASI Preview 1 module carrying component metadata into a component.

use std::{fs, path::PathBuf};
use wit_component::ComponentEncoder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1).map(PathBuf::from);
    let module_path = arguments.next().ok_or("missing module path")?;
    let adapter_path = arguments.next().ok_or("missing reactor adapter path")?;
    let output_path = arguments.next().ok_or("missing output path")?;
    if arguments.next().is_some() {
        return Err(
            "usage: componentize <module.wasm> <reactor-adapter.wasm> <output.wasm>".into(),
        );
    }
    let module = fs::read(module_path)?;
    let adapter = fs::read(adapter_path)?;
    let component = ComponentEncoder::default()
        .module(&module)?
        .validate(true)
        .adapter("wasi_snapshot_preview1", &adapter)?
        .encode()?;
    fs::write(output_path, component)?;
    Ok(())
}
