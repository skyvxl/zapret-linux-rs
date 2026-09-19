//! Flowseal is data: decode bounded bytes, validate effective tar entries, never unpack.
use crate::{
    app_archive::PayloadFile,
    error::{AppError, Result},
};
use flate2::read::MultiGzDecoder;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::PathBuf,
};
pub const EXPANDED_LIMIT: u64 = 64 * 1024 * 1024;
pub const ENTRY_LIMIT: usize = 1024;
pub const GENERATED_LISTS: &[&str] = &[
    "list-general-user.txt",
    "list-exclude-user.txt",
    "ipset-exclude-user.txt",
];
fn fail(e: impl std::fmt::Display) -> AppError {
    AppError::new("archive", e.to_string())
}
fn basename(s: &str) -> bool {
    crate::service_fs::owned_data_basename(s) && s.len() <= 200 && !s.ends_with([' ', '.'])
}
pub fn strategy_name(s: &str) -> bool {
    basename(s) && s.starts_with("general") && s.ends_with(".bat")
}
pub fn file_limit(s: &str) -> Option<u64> {
    if s == "bin/nfqws" {
        return Some(2 * 1024 * 1024);
    }
    if let Some(s) = s.strip_prefix("strategies/") {
        return strategy_name(s).then_some(64 * 1024);
    }
    if let Some(s) = s.strip_prefix("assets/bin/") {
        return (basename(s) && s.ends_with(".bin")).then_some(2 * 1024 * 1024);
    }
    if let Some(s) = s.strip_prefix("assets/lists/") {
        return (basename(s) && (s.ends_with(".txt") || s.ends_with(".txt.backup")))
            .then_some(2 * 1024 * 1024);
    }
    None
}
fn path_text(bytes: &[u8]) -> Result<String> {
    let s = std::str::from_utf8(bytes)
        .map_err(fail)?
        .trim_end_matches('/');
    if s.is_empty()
        || s.len() > 1024
        || s.starts_with('/')
        || s.contains('\\')
        || s.chars().any(char::is_control)
        || s.split('/').any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(fail("Небезопасный путь tar"));
    }
    Ok(s.to_string())
}
pub fn payload(compressed: &[u8], expected_revision: Option<&str>) -> Result<Vec<PayloadFile>> {
    if compressed.len() > 16 * 1024 * 1024 {
        return Err(fail("Сжатый архив превышает 16 MiB"));
    }
    // Consume every gzip member and its trailer, including bytes after tar's end markers.
    let mut expanded = Vec::new();
    MultiGzDecoder::new(compressed)
        .take(EXPANDED_LIMIT + 1)
        .read_to_end(&mut expanded)
        .map_err(fail)?;
    if expanded.len() as u64 > EXPANDED_LIMIT {
        return Err(fail("Распакованный архив превышает 64 MiB"));
    }
    let mut raw = tar::Archive::new(expanded.as_slice());
    raw.set_ignore_zeros(true);
    for (index, entry) in raw.entries().map_err(fail)?.raw(true).enumerate() {
        if index >= ENTRY_LIMIT {
            return Err(fail("Слишком много записей tar"));
        }
        let mut entry = entry.map_err(fail)?;
        let ty = entry.header().entry_type();
        if !(ty.is_file()
            || ty.is_dir()
            || ty.is_pax_local_extensions()
            || ty.is_pax_global_extensions()
            || ty.is_gnu_longname())
        {
            return Err(fail("Ссылки, sparse и специальные записи tar запрещены"));
        }
        if ty.is_pax_local_extensions() || ty.is_pax_global_extensions() {
            for extension in entry.pax_extensions().map_err(fail)?.into_iter().flatten() {
                let extension = extension.map_err(fail)?;
                if (ty.is_pax_global_extensions() && extension.key_bytes() != b"comment")
                    || extension.key_bytes() == b"size"
                    || extension.key_bytes().starts_with(b"GNU.sparse")
                    || extension.key_bytes() == b"SCHILY.filetype"
                {
                    return Err(fail("Sparse tar запрещён"));
                }
            }
        }
        std::io::copy(&mut entry, &mut std::io::sink()).map_err(fail)?;
    }
    let mut archive = tar::Archive::new(expanded.as_slice());
    archive.set_ignore_zeros(true);
    let mut seen = BTreeMap::<String, bool>::new();
    let mut aliases = BTreeSet::new();
    let mut root = None;
    let mut files = Vec::new();
    let mut total = 0;
    for entry in archive.entries().map_err(fail)? {
        let mut entry = entry.map_err(fail)?;
        let ty = entry.header().entry_type();
        if ty.is_pax_global_extensions() {
            std::io::copy(&mut entry, &mut std::io::sink()).map_err(fail)?;
            continue;
        }
        if ty.is_file() && entry.path_bytes().ends_with(b"/") {
            return Err(fail("Путь обычного файла tar заканчивается разделителем"));
        }
        let path = path_text(&entry.path_bytes())?;
        if !(ty.is_file() || ty.is_dir()) {
            return Err(fail("Допустимы только обычные файлы и каталоги tar"));
        }
        let first = path.split('/').next().unwrap_or("");
        let revision = first.strip_prefix("zapret-discord-youtube-").unwrap_or("");
        if revision.len() != 40 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(fail("Неизвестный корень Flowseal tar"));
        }
        if expected_revision.is_some_and(|expected| expected != revision) {
            return Err(fail(
                "Корень архива отличается от разрешённого GitHub commit",
            ));
        }
        if root.as_ref().is_some_and(|r| r != first) {
            return Err(fail("Несколько корней Flowseal tar"));
        }
        root = Some(first.to_string());
        if seen.insert(path.clone(), ty.is_dir()).is_some() {
            return Err(fail("Повторный путь tar"));
        }
        for (other, directory) in &seen {
            if (path.starts_with(&format!("{other}/")) && !directory)
                || (other.starts_with(&format!("{path}/")) && !ty.is_dir())
            {
                return Err(fail("Конфликт файла и каталога tar"));
            }
        }
        if ty.is_dir() {
            if entry.size() != 0 {
                return Err(fail("Каталог tar содержит данные"));
            }
            continue;
        }
        let relative = path.strip_prefix(&format!("{first}/")).unwrap_or("");
        let target = if strategy_name(relative) {
            Some(format!("strategies/{relative}"))
        } else if relative.starts_with("bin/") || relative.starts_with("lists/") {
            Some(format!("assets/{relative}"))
        } else {
            None
        };
        if let Some(target) = target.filter(|s| file_limit(s).is_some()) {
            if !aliases.insert(target.to_lowercase()) {
                return Err(fail("Неоднозначный регистр имени Flowseal"));
            }
            if GENERATED_LISTS
                .iter()
                .any(|name| target == format!("assets/lists/{name}"))
            {
                return Err(fail(
                    "Upstream конфликтует с локальным пустым пользовательским списком",
                ));
            }
            let limit = file_limit(&target).unwrap_or(0);
            if entry.size() > limit {
                return Err(fail("Файл Flowseal превышает лимит"));
            }
            let mut bytes = Vec::new();
            entry
                .by_ref()
                .take(limit + 1)
                .read_to_end(&mut bytes)
                .map_err(fail)?;
            if bytes.len() as u64 > limit || bytes.len() as u64 != entry.size() {
                return Err(fail("Некорректный размер Flowseal"));
            }
            total += bytes.len() as u64;
            if total > EXPANDED_LIMIT {
                return Err(fail("Слишком много данных Flowseal"));
            }
            files.push(PayloadFile {
                relative: PathBuf::from(target),
                bytes,
                executable: false,
            });
        } else {
            std::io::copy(&mut entry, &mut std::io::sink()).map_err(fail)?;
        }
    }
    if !files.iter().any(|f| f.relative.starts_with("strategies")) {
        return Err(fail("Архив не содержит стратегий"));
    }
    Ok(files)
}
