//! Shared helpers for the root (fanotify) integration tests.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// A test-owned tmpfs mount. Protected and allowed fixtures live here so
/// `FAN_MARK_FILESYSTEM` marks only this filesystem — never the root filesystem
/// — and the unmount leaves nothing behind. Root only (the `mount` call).
// WO-154@v1: isolate permission-loop tests from unrelated host filesystems.
// WO-155@v1: remove supervised-tree fixtures when each gate test ends.
pub struct TestFs {
    pub root: PathBuf,
}

// WO-154@v1: provide an isolated filesystem for permission-loop tests.
// WO-155@v1: own cleanup of supervised-tree fixtures as one resource.
impl TestFs {
    // WO-154@v1: mount only the filesystem exercised by each gate test.
    // WO-155@v1: give each supervised-tree test a distinct fixture root.
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
    // WO-154@v1: keep protected and allowed paths on the isolated mount.
    // WO-155@v1: keep supervised-tree artifacts under the owned fixture root.
    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

// WO-154@v1: release the isolated permission-loop filesystem after each test.
// WO-155@v1: tear down supervised-tree fixtures even on unwinding.
impl Drop for TestFs {
    // WO-154@v1: unmount before removing the permission-loop fixture root.
    // WO-155@v1: leave no mounted supervised-tree fixture behind.
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.root).status();
        let _ = fs::remove_dir_all(&self.root);
    }
}
