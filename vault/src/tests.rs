//! Tests for the Vault filesystem, over an in-memory block device.

use super::*;

/// A RAM-backed block device for tests.
struct RamDisk {
    blocks: Vec<[u8; BLOCK]>,
}

impl RamDisk {
    fn new(blocks: usize) -> RamDisk {
        RamDisk {
            blocks: vec![[0u8; BLOCK]; blocks],
        }
    }
}

impl BlockDevice for RamDisk {
    fn read_block(&mut self, lba: u64, buf: &mut [u8; BLOCK]) -> Result<(), Error> {
        let b = self.blocks.get(lba as usize).ok_or(Error::Device)?;
        *buf = *b;
        Ok(())
    }
    fn write_block(&mut self, lba: u64, buf: &[u8; BLOCK]) -> Result<(), Error> {
        let b = self.blocks.get_mut(lba as usize).ok_or(Error::Device)?;
        *b = *buf;
        Ok(())
    }
    fn blocks(&self) -> u64 {
        self.blocks.len() as u64
    }
}

fn fresh(blocks: usize) -> Vault<RamDisk> {
    match Vault::format(RamDisk::new(blocks)) {
        Ok(v) => v,
        Err(e) => panic!("format failed: {e:?}"),
    }
}

#[test]
fn format_is_empty() {
    let v = fresh(64);
    assert_eq!(v.blocks(), 64);
    assert_eq!(v.file_count(), 0);
    assert_eq!(v.free_blocks(), 63); // block 0 is the superblock
    assert!(v.lookup(b"anything").is_none());
}

#[test]
fn create_then_read() {
    let mut v = fresh(64);
    let data = b"the gate is shut and barred";
    assert!(v.create(b"note.txt", data).is_ok());
    assert_eq!(v.file_count(), 1);

    let mut out = [0u8; 64];
    let n = match v.read(b"note.txt", &mut out) {
        Ok(n) => n,
        Err(e) => panic!("read failed: {e:?}"),
    };
    assert_eq!(n, data.len());
    assert_eq!(&out[..n], data);
}

#[test]
fn multi_block_file_round_trips() {
    let mut v = fresh(64);
    // A file spanning several blocks (1500 bytes -> 3 blocks).
    let data: Vec<u8> = (0..1500u32).map(|i| (i * 7) as u8).collect();
    assert!(v.create(b"big", &data).is_ok());
    // 3 data blocks allocated after block 0.
    assert_eq!(v.free_blocks(), 63 - 3);

    let mut out = vec![0u8; 1500];
    let n = v.read(b"big", &mut out).expect("read");
    assert_eq!(n, 1500);
    assert_eq!(out, data);
}

#[test]
fn persists_across_remount() {
    let disk = {
        let mut v = fresh(64);
        v.create(b"a", b"alpha").expect("create a");
        v.create(b"b", b"bravo").expect("create b");
        v.into_device()
    };
    // Re-open from the same bytes: both files are still there.
    let mut v = Vault::open(disk).expect("open");
    assert_eq!(v.file_count(), 2);
    let mut out = [0u8; 8];
    let n = v.read(b"b", &mut out).expect("read b");
    assert_eq!(&out[..n], b"bravo");
}

#[test]
fn files_get_separate_extents() {
    let mut v = fresh(64);
    v.create(b"one", b"111").expect("one");
    v.create(b"two", b"222").expect("two");
    let one = v.lookup(b"one").expect("one entry");
    let two = v.lookup(b"two").expect("two entry");
    assert_ne!(one.start, two.start);
    // Reading one does not see the other's bytes.
    let mut out = [0u8; 3];
    v.read(b"one", &mut out).expect("read one");
    assert_eq!(&out, b"111");
}

#[test]
fn duplicate_name_is_refused() {
    let mut v = fresh(64);
    v.create(b"dup", b"first").expect("first");
    assert_eq!(v.create(b"dup", b"second"), Err(Error::Exists));
    // The original is untouched.
    let mut out = [0u8; 8];
    let n = v.read(b"dup", &mut out).expect("read");
    assert_eq!(&out[..n], b"first");
}

#[test]
fn bad_names_are_refused() {
    let mut v = fresh(64);
    assert_eq!(v.create(b"", b"x"), Err(Error::BadName));
    assert_eq!(
        v.create(b"this name is far too long", b"x"),
        Err(Error::BadName)
    );
}

#[test]
fn missing_file_is_not_found() {
    let mut v = fresh(64);
    let mut out = [0u8; 8];
    assert_eq!(v.read(b"ghost", &mut out), Err(Error::NotFound));
}

#[test]
fn directory_fills_up() {
    let mut v = fresh(256);
    for i in 0..MAX_FILES {
        let name = [b'f', b'0' + i as u8];
        v.create(&name, b"x").expect("create");
    }
    assert_eq!(v.create(b"one-too-many", b"x"), Err(Error::DirectoryFull));
}

#[test]
fn running_out_of_space_is_refused() {
    // 4 blocks: block 0 is the superblock, 3 free.
    let mut v = fresh(4);
    // A 3-block file fits exactly.
    assert!(v.create(b"fits", &[0u8; 3 * BLOCK]).is_ok());
    assert_eq!(v.free_blocks(), 0);
    // Anything more does not.
    assert_eq!(v.create(b"nope", b"x"), Err(Error::NoSpace));
}

#[test]
fn short_buffer_reports_true_length() {
    let mut v = fresh(64);
    v.create(b"long", b"0123456789").expect("create");
    let mut out = [0u8; 4];
    let n = v.read(b"long", &mut out).expect("read");
    assert_eq!(n, 10); // true length
    assert_eq!(&out, b"0123"); // only what fit
}

#[test]
fn bad_magic_is_rejected() {
    let disk = RamDisk::new(64); // all zeros, no magic
    assert_eq!(Vault::open(disk).err(), Some(Error::BadMagic));
}

#[test]
fn corrupt_entry_is_rejected() {
    // Forge a superblock whose entry points past the end of the device.
    let mut disk = RamDisk::new(8);
    let mut sb = [0u8; BLOCK];
    sb[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(&MAGIC);
    wr_u32(&mut sb, OFF_BLOCKS, 8);
    wr_u32(&mut sb, OFF_NEXT_FREE, 1);
    wr_u32(&mut sb, OFF_FILE_COUNT, 1);
    let base = HEADER;
    sb[base + E_NAME] = b'x';
    wr_u32(&mut sb, base + E_START, 7);
    wr_u32(&mut sb, base + E_LEN, 10 * BLOCK as u32); // runs off the end
    wr_u32(&mut sb, base + E_FLAGS, FLAG_USED);
    disk.write_block(0, &sb).expect("seed");
    assert_eq!(Vault::open(disk).err(), Some(Error::Corrupt));
}

#[test]
fn write_creates_then_replaces() {
    let mut v = fresh(64);
    v.write(b"k", b"first").expect("write");
    v.write(b"k", b"second, a longer value").expect("overwrite");
    assert_eq!(v.file_count(), 1);
    let mut out = [0u8; 32];
    let n = v.read(b"k", &mut out).expect("read");
    assert_eq!(&out[..n], b"second, a longer value");
}

#[test]
fn delete_reclaims_space_and_compacts() {
    let mut v = fresh(64);
    v.create(b"a", &[1u8; 1000]).expect("a"); // 2 blocks
    v.create(b"b", &[2u8; 500]).expect("b"); // 1 block
    v.create(b"c", &[3u8; 1500]).expect("c"); // 3 blocks
    assert_eq!(v.free_blocks(), 63 - 6);
    let c_before = v.lookup(b"c").expect("c entry").start;

    // Delete the first file; b and c slide down into its 2-block gap.
    v.delete(b"a").expect("delete a");
    assert_eq!(v.file_count(), 2);
    assert_eq!(v.free_blocks(), 63 - 4);
    assert_eq!(v.lookup(b"c").expect("c entry").start, c_before - 2);

    // The survivors still read back exactly.
    let mut out = vec![0u8; 1500];
    let n = v.read(b"c", &mut out).expect("read c");
    assert_eq!(n, 1500);
    assert!(out.iter().all(|&x| x == 3));
    let n = v.read(b"b", &mut out).expect("read b");
    assert_eq!(n, 500);
    assert!(out[..500].iter().all(|&x| x == 2));

    // The deleted file is gone.
    assert_eq!(v.read(b"a", &mut out), Err(Error::NotFound));
}

#[test]
fn delete_frees_space_for_reuse() {
    let mut v = fresh(4); // 3 free blocks
    v.create(b"big", &[9u8; 3 * BLOCK]).expect("fills the disk");
    assert_eq!(v.free_blocks(), 0);
    v.delete(b"big").expect("delete");
    assert_eq!(v.free_blocks(), 3);
    // The reclaimed space takes a fresh file.
    v.create(b"new", &[7u8; 3 * BLOCK])
        .expect("reuse the space");
}

#[test]
fn deleting_a_missing_file_is_not_found() {
    let mut v = fresh(64);
    assert_eq!(v.delete(b"ghost"), Err(Error::NotFound));
}

#[test]
fn an_overwrite_too_large_keeps_the_old_file() {
    let mut v = fresh(4); // 3 free blocks
    v.write(b"f", &[1u8; BLOCK]).expect("one block");
    // Replacing it with four blocks cannot fit (2 free + 1 reclaimed = 3).
    assert_eq!(v.write(b"f", &[2u8; 4 * BLOCK]), Err(Error::NoSpace));
    // The original survives untouched.
    let mut out = [0u8; BLOCK];
    let n = v.read(b"f", &mut out).expect("read");
    assert_eq!(n, BLOCK);
    assert!(out.iter().all(|&x| x == 1));
}

#[test]
fn delete_persists_across_remount() {
    let disk = {
        let mut v = fresh(64);
        v.create(b"a", b"alpha").expect("a");
        v.create(b"b", b"bravo").expect("b");
        v.delete(b"a").expect("delete a");
        v.into_device()
    };
    let mut v = Vault::open(disk).expect("open");
    assert_eq!(v.file_count(), 1);
    let mut out = [0u8; 8];
    let n = v.read(b"b", &mut out).expect("read b");
    assert_eq!(&out[..n], b"bravo");
}

#[test]
fn list_visits_every_file() {
    let mut v = fresh(64);
    v.create(b"a", b"1").expect("a");
    v.create(b"b", b"2").expect("b");
    v.create(b"c", b"3").expect("c");
    let mut names = Vec::new();
    v.for_each(|e| names.push(e.name().to_vec()));
    assert_eq!(names, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
}
