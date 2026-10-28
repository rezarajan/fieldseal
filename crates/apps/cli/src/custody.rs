//! Development key custody (see [`fieldseal_adapters_file::custody`]) and the CLI's randomness.

pub use fieldseal_adapters_file::custody::DirCustody;

/// Randomness from the operating system, for the factory and device sides of the CLI.
pub struct OsRandom;

impl fieldseal_trust::ports::RandomSource for OsRandom {
    fn fill(&self, buf: &mut [u8]) {
        // A failure to read the operating system's generator must never yield predictable
        // bytes: stop the process rather than continue.
        if std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, buf)).is_err() {
            eprintln!("fieldseal: the operating system's random generator is unavailable");
            std::process::exit(crate::outcome::exit::CONFIG.into());
        }
    }
}
