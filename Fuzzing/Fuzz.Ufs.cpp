// Fuzz.Ufs.cpp - libFuzzer entry for the NanaZip UFS/UFS2 handler.
//
// The UFS handler's Open() checks these superblock fields (all must pass or
// the handler immediately returns S_FALSE and the entire iteration is wasted):
//
//   fs_magic        (+1372, int32)  == 0x011954 (UFS1) or 0x19540119 (UFS2)
//   fs_sblockloc    (+1000, int64)  == 8192 (UFS1) or 65536 (UFS2)
//   fs_frag         (+56,   int32)  >= 1
//   fs_ncg          (+44,   uint32) >= 1
//   fs_bsize        (+48,   int32)  >= 4096 (MINBSIZE)
//   fs_sbsize       (+104,  int32)  in [sizeof(fs)=1376, SBLOCKSIZE=8192]
//   fs_fsize        (+52,   int32)  — must equal fs_bsize / fs_frag
//
// After Open, GetAllPaths → GetInodeInformation reads the root inode's
// di_size (attacker-controlled uint64) and loops adding BlockSize per
// iteration until ActualFileSize >= di_size. With di_size=2^64-1 and
// BlockSize=4096, that's 4.5e15 vector pushes → instant OOM/hang.
//
// The custom mutator fixes the superblock gate fields and caps the root
// inode's di_size so every mutation reaches the parser's deep logic.
#include "NanaZip.Codecs.Fuzz.h"
#include <cstring>
#include <cstdint>

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

static void WriteLE32(std::uint8_t* p, std::int32_t v)
{
    auto u = static_cast<std::uint32_t>(v);
    p[0] = static_cast<std::uint8_t>(u);
    p[1] = static_cast<std::uint8_t>(u >> 8);
    p[2] = static_cast<std::uint8_t>(u >> 16);
    p[3] = static_cast<std::uint8_t>(u >> 24);
}

static void WriteLE64(std::uint8_t* p, std::int64_t v)
{
    auto u = static_cast<std::uint64_t>(v);
    WriteLE32(p, static_cast<std::int32_t>(u));
    WriteLE32(p + 4, static_cast<std::int32_t>(u >> 32));
}

static std::uint64_t ReadLE64(const std::uint8_t* p)
{
    return static_cast<std::uint64_t>(p[0])
        | (static_cast<std::uint64_t>(p[1]) << 8)
        | (static_cast<std::uint64_t>(p[2]) << 16)
        | (static_cast<std::uint64_t>(p[3]) << 24)
        | (static_cast<std::uint64_t>(p[4]) << 32)
        | (static_cast<std::uint64_t>(p[5]) << 40)
        | (static_cast<std::uint64_t>(p[6]) << 48)
        | (static_cast<std::uint64_t>(p[7]) << 56);
}

// Superblock field offsets (relative to start of struct fs, sizeof==1376)
static constexpr int kOff_fs_iblkno      = 16;
static constexpr int kOff_fs_ncg         = 44;
static constexpr int kOff_fs_bsize       = 48;
static constexpr int kOff_fs_fsize       = 52;
static constexpr int kOff_fs_frag        = 56;
static constexpr int kOff_fs_sbsize      = 104;
static constexpr int kOff_fs_ipg         = 184;
static constexpr int kOff_fs_fpg         = 188;
static constexpr int kOff_fs_sblockloc   = 1000;
static constexpr int kOff_fs_maxsymlinklen = 1320;
static constexpr int kOff_fs_magic       = 1372;

// UFS constants
static constexpr std::int32_t  kFS_UFS1_MAGIC = 0x011954;
static constexpr std::int32_t  kFS_UFS2_MAGIC = 0x19540119;
static constexpr std::size_t   kSBLOCK_UFS1   = 8192;
static constexpr std::size_t   kSBLOCK_UFS2   = 65536;
static constexpr std::int32_t  kSBLOCKSIZE    = 8192;
static constexpr std::int32_t  kBLOCK_SIZE    = 4096;
static constexpr std::int32_t  kFS_STRUCT_SIZE = 1376;
static constexpr std::uint32_t kUFS_ROOTINO   = 2;

// Inode sizes
static constexpr std::size_t kUFS1_DINODE_SIZE = 128;
static constexpr std::size_t kUFS2_DINODE_SIZE = 256;

// di_size offsets within dinode structs
static constexpr int kUFS1_di_size = 8;   // uint64 at offset 8
static constexpr int kUFS2_di_size = 16;  // uint64 at offset 16

// Maximum di_size we allow (1 MiB) — prevents OOM in GetInodeInformation
static constexpr std::uint64_t kMaxDiSize = 1048576;

// Minimum image size: UFS1 superblock at 8192, needs at least sb + 1376 bytes
static constexpr std::size_t kMinUfs1 = kSBLOCK_UFS1 + kFS_STRUCT_SIZE;  // 9568
// UFS2 at 65536
static constexpr std::size_t kMinUfs2 = kSBLOCK_UFS2 + kFS_STRUCT_SIZE;  // 66912

extern "C" size_t LLVMFuzzerCustomMutator(
    uint8_t* Data, size_t Size, size_t MaxSize, unsigned int Seed)
{
    size_t NewSize = LLVMFuzzerMutate(Data, Size, MaxSize);

    // Decide UFS1 vs UFS2 based on seed parity — gives both formats coverage
    bool isUfs2 = (Seed & 1) != 0;
    std::size_t sbOff = isUfs2 ? kSBLOCK_UFS2 : kSBLOCK_UFS1;
    std::size_t minSize = isUfs2 ? kMinUfs2 : kMinUfs1;

    if (NewSize < minSize)
    {
        if (MaxSize < minSize)
            return NewSize;
        std::memset(Data + NewSize, 0, minSize - NewSize);
        NewSize = minSize;
    }

    std::uint8_t* sb = Data + sbOff;

    // --- Fix superblock gate fields ---
    WriteLE32(sb + kOff_fs_magic, isUfs2 ? kFS_UFS2_MAGIC : kFS_UFS1_MAGIC);
    WriteLE64(sb + kOff_fs_sblockloc, static_cast<std::int64_t>(sbOff));
    WriteLE32(sb + kOff_fs_bsize, kBLOCK_SIZE);
    WriteLE32(sb + kOff_fs_fsize, kBLOCK_SIZE);
    WriteLE32(sb + kOff_fs_frag, 1);
    WriteLE32(sb + kOff_fs_ncg, 1);
    WriteLE32(sb + kOff_fs_sbsize, kSBLOCKSIZE);
    WriteLE32(sb + kOff_fs_iblkno, 4);
    WriteLE32(sb + kOff_fs_ipg, 16);
    WriteLE32(sb + kOff_fs_fpg, 100);
    WriteLE32(sb + kOff_fs_maxsymlinklen, 60);

    // --- Cap di_size for ALL inodes in the inode block to prevent OOM ---
    // iblkno(4) * fsize(4096) = 16384 is the inode block start.
    // fs_ipg = 16, so inodes 0..15 are in this block.
    // Cap each inode's di_size to kMaxDiSize to prevent the
    // GetInodeInformation loop from doing O(di_size/BlockSize) pushes.
    std::size_t inodeSize = isUfs2 ? kUFS2_DINODE_SIZE : kUFS1_DINODE_SIZE;
    int diSizeFieldOff = isUfs2 ? kUFS2_di_size : kUFS1_di_size;
    std::size_t inodeBlockOff = 4 * kBLOCK_SIZE;  // iblkno * fsize

    for (unsigned ino = 0; ino < 16; ++ino)
    {
        std::size_t off = inodeBlockOff + ino * inodeSize + diSizeFieldOff;
        if (off + 8 > NewSize)
            break;
        std::uint64_t diSize = ReadLE64(Data + off);
        if (diSize > kMaxDiSize)
        {
            diSize = (diSize % kMaxDiSize) + 1;
            WriteLE64(Data + off, static_cast<std::int64_t>(diSize));
        }
    }

    return NewSize;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    NanaZip::Fuzz::RunFuzzCase(0, data, size);
    return 0;
}
