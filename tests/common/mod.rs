//! Shared helpers for the root (fanotify) integration tests.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// A test-owned tmpfs mount. Protected and allowed fixtures live here so
/// `FAN_MARK_FILESYSTEM` marks only this filesystem — never the root filesystem
/// — and the unmount leaves nothing behind. Root only (the `mount` call).
pub struct TestFs {
    pub root: PathBuf,
}

impl TestFs {
    pub fn new(tag: &str) -> Self {
        let root = PathBuf::from(format!(
            "/var/tmp/bulwark-testfs-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create test fs dir");
        let st = Command::new("mount")
            .args([
                "-t",
                "tmpfs",
                "tmpfs",
                "-o",
                "size=16m",
                root.to_str().unwrap(),
            ])
            .status()
            .expect("run mount");
        assert!(st.success(), "tmpfs mount of {} failed", root.display());
        TestFs { root }
    }

    /// A fixture path on this test filesystem.
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TestFs {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.root).status();
        let _ = fs::remove_dir_all(&self.root);
    }
}
