# ext2 disk-layout golden fixtures

This directory holds byte-for-byte slices of a deterministic
`mkfs.ext2` image, used by the `disk.rs` unit tests in this module to
pin the rev-0 on-disk layout against a known-good reference.

The generator is:

```sh
dd if=/dev/zero of=golden.img bs=1024 count=1024
E2FSPROGS_FAKE_TIME=1000000000 mkfs.ext2 \
    -b 1024 -N 64 -I 128 -F \
    -U 00000000-0000-0000-0000-000000000001 \
    -E hash_seed=11111111-2222-3333-4444-555555555555 \
    -M / -t ext2 \
    -O '^dir_index,^has_journal,^ext_attr,^resize_inode' \
    golden.img
```

`E2FSPROGS_FAKE_TIME`, the fixed UUID, and the fixed hash seed make the
output deterministic; the `-O ^...` set disables the post-rev-0
features vibix does not read.

The four `golden_*.bin` slices above are cut from the 1 MiB image.

A **second** smaller fixture, `golden.img` (64 KiB, 64 × 1 KiB blocks,
16 inodes), is committed whole and used by
`kernel/tests/ext2_mount.rs` (issue #558) as a full backing-device
image for the mount path. Its generator is the same `mkfs.ext2`
invocation with `count=64` and `-N 16` instead of `count=1024` and
`-N 64`:

```sh
dd if=/dev/zero of=golden.img bs=1024 count=64
E2FSPROGS_FAKE_TIME=1000000000 mkfs.ext2 \
    -b 1024 -N 16 -I 128 -F \
    -U 00000000-0000-0000-0000-000000000001 \
    -E hash_seed=11111111-2222-3333-4444-555555555555 \
    -M / -t ext2 \
    -O '^dir_index,^has_journal,^ext_attr,^resize_inode' \
    golden.img
```

## Files

| File | Source byte range | Size | Content |
|---|---|---|---|
| `golden_superblock.bin` | `[1024, 2048)` | 1024 | rev-1 superblock (1 MiB image) |
| `golden_bgd0.bin` | `[2048, 2080)` | 32 | first group descriptor (1 MiB image) |
| `golden_root_inode.bin` | `[5248, 5376)` | 128 | root inode (ino 2) (1 MiB image) |
| `golden_root_dir.bin` | `[13312, 13376)` | 64 | root dir first block prefix (1 MiB image) |
| `golden.img` | `[0, 65536)` | 65536 | full 64 KiB mkfs.ext2 image (mount tests) |
| `read_test.img` | — | 1048576 | 1 MiB mkfs.ext2 image pre-populated with `small.bin` (26 B), `large.bin` (300 KiB crossing single-indirect), `hole.bin` (3 KiB dense), and `sparse.bin` (11 KiB with logical blocks 1..9 hole-punched via `debugfs set_inode_field block[n] 0`). Used by `kernel/tests/ext2_file_read.rs` (issue #561). |

## `read_test.img` generator

```sh
dd if=/dev/zero of=read_test.img bs=1024 count=1024
E2FSPROGS_FAKE_TIME=1000000000 mkfs.ext2 \
    -b 1024 -N 64 -I 128 -F \
    -U 00000000-0000-0000-0000-000000000002 \
    -E hash_seed=11111111-2222-3333-4444-555555555555 \
    -M / -t ext2 \
    -O '^dir_index,^has_journal,^ext_attr,^resize_inode,^sparse_super' \
    read_test.img

# small.bin: 26-byte greeting, single direct block.
printf 'hello ext2 read path #561\n' > small.bin

# large.bin: 300 × 1 KiB blocks with per-block markers, crosses the
# 12-direct → single-indirect boundary at logical block 12.
python3 -c '
data = bytearray()
for b in range(300):
    head = f"BLK{b:05d}".encode("ascii")
    body = bytes([(b * 131 + i) & 0xff for i in range(1024 - len(head))])
    data.extend(head + body)
open("large.bin", "wb").write(bytes(data))
'

# hole.bin: dense pattern (no sparse) — the name is historical; kept
# for completeness even though sparse.bin carries the hole test.
python3 -c "open('hole_raw.bin','wb').write(b'A'*512 + b'\x00'*2048 + b'B'*512)"

# sparse.bin: logical block 0 and 10 live, 1..9 hole-punched. Written
# as 11 KiB of non-zero content first, then `set_inode_field block[i]
# 0` zeroes the direct slots in-place.
python3 -c "open('prehole.bin','wb').write(b'X'*1024 + b'H'*9*1024 + b'Z'*1024)"

debugfs -w -R 'write small.bin small.bin'       read_test.img
debugfs -w -R 'write large.bin large.bin'       read_test.img
debugfs -w -R 'write hole_raw.bin hole.bin'     read_test.img
debugfs -w -R 'write prehole.bin sparse.bin'    read_test.img
# Hole-punch sparse.bin — inode number matches the fourth `write`.
for i in 1 2 3 4 5 6 7 8 9; do
    echo "set_inode_field <15> block[$i] 0"
done | debugfs -w -f /dev/stdin read_test.img
```

Assigned inos on a deterministic `mkfs.ext2` run of the above: `small.bin = 12`, `large.bin = 13`, `hole.bin = 14`, `sparse.bin = 15`.

Byte offsets for the 1 MiB slices are computed from:
- Superblock at byte 1024 regardless of block size.
- Group descriptor table at block 2 (byte 2048) on 1 KiB-block volumes.
- Inode table at block 5 per `dumpe2fs`; root inode (ino 2) is at slot
  `(2 - 1) * 128 = 128` bytes into the table, i.e., byte
  `5 * 1024 + 128 = 5248`.
- Root directory data at `i_block[0] = 13`, i.e., byte `13 * 1024 =
  13312`. The records fit in the first 42 bytes; 64 bytes covers the
  trailing padding of the third record's name.

To regenerate the fixtures (e.g., if the driver learns a new field and
you want to expand the decoded surface), run the generator above on a
host with `e2fsprogs >= 1.47` and re-`dd` the four slices. Any host
with a modern `mkfs.ext2` produces byte-identical output for these
inputs.
