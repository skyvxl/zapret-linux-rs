use crate::error::{AppError, Result};
use std::{fs::File, io::Read, path::Path};

pub fn read_text(path: &Path) -> Result<String> {
    const LIMIT: u64 = 1024 * 1024;
    let file =
        File::open(path).map_err(|e| AppError::new("io", format!("{}: {e}", path.display())))?;
    if !file
        .metadata()
        .map_err(|e| AppError::new("io", e.to_string()))?
        .is_file()
    {
        return Err(AppError::new("io", "Ожидается обычный файл"));
    }
    let mut data = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut data)
        .map_err(|e| AppError::new("io", e.to_string()))?;
    if data.len() as u64 > LIMIT {
        return Err(AppError::new("input", "Файл превышает 1 MiB"));
    }
    String::from_utf8(data).map_err(|_| AppError::new("input", "Ожидается UTF-8"))
}
