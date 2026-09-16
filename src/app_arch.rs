#[derive(Debug, Clone, Copy)]
pub struct EngineSpec {
    pub directory: &'static str,
    pub size: usize,
    pub sha256: &'static str,
}

pub fn engine_spec_for(
    architecture: &str,
    little_endian: bool,
) -> std::result::Result<EngineSpec, String> {
    let engine = match (architecture, little_endian) {
        ("x86_64", _) => EngineSpec {
            directory: "linux-x86_64",
            size: 126_884,
            sha256: "e57db44af46835f68a8cacbf98267c694ee863e27622a8c3a3609eb14ebad11c",
        },
        ("x86", _) => EngineSpec {
            directory: "linux-x86",
            size: 122_688,
            sha256: "8828debd263a4b0c437704f598c612e9ffe8615eac93c6152877dcca10f06f52",
        },
        ("aarch64", _) => EngineSpec {
            directory: "linux-arm64",
            size: 126_756,
            sha256: "63834d530cfd53381be99b02e0f0529ff320c9f043daa2fe49bd54609a9ac49f",
        },
        ("arm", _) => EngineSpec {
            directory: "linux-arm",
            size: 117_332,
            sha256: "8361ba841afcde246882133cafe7c6dd79857dbf2cc098a4dd0e94e8b95e4789",
        },
        ("powerpc", _) => EngineSpec {
            directory: "linux-ppc",
            size: 128_936,
            sha256: "a2aef97ced04680cde818b357544f39fd508d62a5d7518372173d69bc4c7f0d6",
        },
        ("mips", true) => EngineSpec {
            directory: "linux-mipsel",
            size: 146_276,
            sha256: "db0f5cc1fa5a922d119f2e845ca0ee6385593e48ad40d8eacb8217b1f64c57ee",
        },
        ("mips", false) => EngineSpec {
            directory: "linux-mips",
            size: 145_760,
            sha256: "0e191cdaf5c51e68a5466d67aca6a58b9d73a430e37c6aad07d4cafced4d2976",
        },
        ("mips64", false) => EngineSpec {
            directory: "linux-mips64",
            size: 374_656,
            sha256: "44922af6df7973db7bfe110727cf2961690a0b9f4e97b09c5ba1233d530cbb57",
        },
        _ => {
            return Err(format!(
                "Архитектура {architecture} не поддерживается закреплённым nfqws v72.9"
            ));
        }
    };
    Ok(engine)
}
