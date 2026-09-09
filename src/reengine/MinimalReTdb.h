#pragma once

// Minimal RE Engine TypeDB (TDB) layout subset for TDB **82** and **83** only.
//
// Adapted from praydog/REFramework @ b6baf6b406efc65e077b99cb4d9ad25b0a0a9095:
//   shared/sdk/RETypeDB.hpp        (namespaces tdb82 / tdb83, RETypeDefVersion84)
//   shared/sdk/RETypeDefinition.hpp
//   shared/sdk/RETypeDefDispatch.hpp
//   shared/sdk/RETypeDB.cpp        (RETypeDB::get_type / get_method / get_string,
//                                   REMethodDefinition::get_name / get_function)
//   shared/sdk/RETypeDefinition.cpp (get_name / get_namespace)
//
// REFramework compiles one binary per game with a fixed TDB_VER, so it can pick
// a single struct layout at compile time. Capcom Patcher must support the two
// modern layouts the six selected games use, so the versioned structs are
// mirrored here with static_asserts and the version-dependent field reads are
// dispatched at runtime on a validated TDB version (82 or 83) - never on a
// `>= 82` rule.
//
// Only the pieces required to resolve `via.render.Renderer` +
// `get_RenderFrame()` are ported. This is not a general RE Engine SDK.

#include <cstddef>
#include <cstdint>

namespace reengine::re_tdb
{
// ---------------------------------------------------------------------------
// Mirrored upstream structs - used only for static_assert layout validation.
// Field reads in RendererBridge.cpp go through the offset/shift constants below
// so a silent MSVC bitfield-packing difference cannot pass unnoticed.
// ---------------------------------------------------------------------------

// shared/sdk/RETypeDefinition.hpp : RETypeDefVersion84 (TDB 74+, stride 0x50).
// TDB 82 and 83 both use this type-definition layout.
// (Upstream RETypeDefinition.hpp applies no #pragma pack here - natural x64
// alignment.)
struct RETypeDefVersion84
{
    uint64_t index : 19;
    uint64_t parent_typeid : 19;
    uint64_t declaring_typeid : 19;
    uint64_t underlying_typeid : 7;

    uint64_t array_typeid_TBD : 19;
    uint64_t element_typeid_TBD : 19;
    uint64_t impl_index : 18;
    uint64_t system_typeid : 7;

    uint32_t type_flags;
    uint32_t size;
    uint32_t fqn_hash;
    uint32_t type_crc;

    uint64_t default_ctor : 22;
    uint64_t member_method : 22;
    uint64_t member_field : 20;

    uint32_t num_member_prop : 12;
    uint32_t member_prop : 19;

    uint32_t unk_data : 26;
    uint32_t object_type : 3;

    int64_t unk_data_before_generics : 26;
    int64_t generics : 26;
    int64_t interfaces : 12;
    void* type;       // sdk::RETypeCLR* (aka REType*)
    void* managed_vt; // ::REObjectInfo*

    uint64_t unk_new_tdb74_uint64;
};
static_assert(sizeof(RETypeDefVersion84) == 0x50, "RETypeDefVersion84 layout drift");
static_assert(offsetof(RETypeDefVersion84, type_flags) == 0x10, "type_flags offset drift");
static_assert(offsetof(RETypeDefVersion84, fqn_hash) == 0x18, "fqn_hash offset drift");
static_assert(offsetof(RETypeDefVersion84, type_crc) == 0x1C, "type_crc offset drift");
static_assert(offsetof(RETypeDefVersion84, type) == 0x38, "type ptr offset drift");

// The impl structs below mirror upstream's `#pragma pack(push, 4)` region in
// shared/sdk/RETypeDB.hpp (tdb82 / tdb83 namespaces).
#pragma pack(push, 4)

// shared/sdk/RETypeDB.hpp : tdb82::RETypeImpl (plain int32 name/namespace).
struct RETypeImpl82
{
    int32_t name_offset;      // 0x0
    int32_t namespace_offset; // 0x4
    int32_t field_size;       // 0x8
    int32_t static_field_size; // 0xc
    uint64_t unk_pad : 33;         // 0x10
    uint64_t num_member_fields : 24;
    uint64_t unk_pad_2 : 7;
    uint16_t num_member_methods; // 0x18
    int16_t num_native_vtable;   // 0x1a
    int16_t interface_id;        // 0x1c
    char pad_1e[0x12];
};
static_assert(sizeof(RETypeImpl82) == 0x30, "RETypeImpl82 layout drift");
static_assert(offsetof(RETypeImpl82, num_member_methods) == 0x18, "num_member_methods offset drift (82)");

// shared/sdk/RETypeDB.hpp : tdb83::RETypeImpl (28-bit packed name/namespace).
struct RETypeImpl83
{
    int64_t name_offset : 28;      // 0x0
    int64_t namespace_offset : 28; // packed in the same int64 as name_offset
    int32_t field_size;            // 0x8
    int32_t static_field_size;     // 0xc
    uint64_t unk_pad : 33;              // 0x10
    uint64_t num_member_fields : 24;
    uint64_t unk_pad_2 : 7;
    uint16_t num_member_methods; // 0x18
    int16_t num_native_vtable;   // 0x1a
    int16_t interface_id;        // 0x1c
    char pad_1e[0x12];
};
static_assert(sizeof(RETypeImpl83) == 0x30, "RETypeImpl83 layout drift");
static_assert(offsetof(RETypeImpl83, field_size) == 0x8, "field_size offset drift (83)");
static_assert(offsetof(RETypeImpl83, num_member_methods) == 0x18, "num_member_methods offset drift (83)");

// shared/sdk/RETypeDB.hpp : tdb82::/tdb83::REMethodDefinition (identical, 0xC).
struct REMethodDefinition
{
    uint32_t declaring_typeid : 19;
    uint32_t params_lo : 13;
    uint32_t impl_id : 19;
    uint32_t params_hi : 13;
    int32_t encoded_offset;
};
static_assert(sizeof(REMethodDefinition) == 0xC, "REMethodDefinition layout drift");
static_assert(offsetof(REMethodDefinition, encoded_offset) == 0x8, "encoded_offset offset drift");

// shared/sdk/RETypeDB.hpp : tdb82::/tdb83::REMethodImpl (identical, 0xC).
struct REMethodImpl
{
    uint16_t attributes_id;
    int16_t vtable_index;
    uint16_t flags;
    uint16_t impl_flags;
    uint32_t name_offset;
};
static_assert(sizeof(REMethodImpl) == 0xC, "REMethodImpl layout drift");
static_assert(offsetof(REMethodImpl, name_offset) == 0x8, "method impl name_offset drift");
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Runtime strides / offsets consumed by RendererBridge.cpp.
// ---------------------------------------------------------------------------

inline constexpr size_t kTypeDefStride = sizeof(RETypeDefVersion84);  // 0x50
inline constexpr size_t kTypeImplStride = 0x30;
inline constexpr size_t kMethodStride = sizeof(REMethodDefinition);   // 0xC
inline constexpr size_t kMethodImplStride = sizeof(REMethodImpl);     // 0xC

// RETypeDefVersion84 field extraction (see the mirrored struct above).
inline constexpr size_t kTypeDefQword1 = 0x08; // array/element/impl_index/system_typeid
inline constexpr int kImplIndexShift = 38;
inline constexpr uint64_t kImplIndexMask = (1ull << 18) - 1;

inline constexpr size_t kTypeDefFqnHash = 0x18;

inline constexpr size_t kTypeDefMemberQword = 0x20; // default_ctor/member_method/member_field
inline constexpr int kMemberMethodShift = 22;
inline constexpr uint64_t kMemberMethodMask = (1ull << 22) - 1;

inline constexpr size_t kTypeDefTypePtr = 0x38;

// tdb82::/tdb83::TDB header (no #pragma pack; 24 uint32 fields then pointers).
// magic(0x00) version(0x04) numTypes(0x08) ... numStringPool(0x58) ...
// modules(0x60) types(0x68) typesImpl(0x70) methods(0x78) methodsImpl(0x80)
// ... stringPool(0xD8) ...
inline constexpr size_t kTdbMagic = 0x00;
inline constexpr size_t kTdbVersion = 0x04;
inline constexpr size_t kTdbNumTypes = 0x08;
inline constexpr size_t kTdbNumMethods = 0x14;
inline constexpr size_t kTdbNumStringPool = 0x58;
inline constexpr size_t kTdbTypesPtr = 0x68;
inline constexpr size_t kTdbTypesImplPtr = 0x70;
inline constexpr size_t kTdbMethodsPtr = 0x78;
inline constexpr size_t kTdbMethodsImplPtr = 0x80;
inline constexpr size_t kTdbStringPoolPtr = 0xD8;

// 'TDB\0' little-endian, matching REFramework's `*(uint32_t*)ptr == *(uint32_t*)"TDB"`.
inline constexpr uint32_t kTdbMagicValue = 0x00424454u;

// RETypeImpl name/namespace field offsets (TDB 82 - plain int32).
inline constexpr size_t kTypeImpl82NameOffset = 0x0;
inline constexpr size_t kTypeImpl82NamespaceOffset = 0x4;
// TDB 83 packs both into the leading int64 as 28-bit fields.
inline constexpr uint64_t kTypeImpl83OffsetMask = (1ull << 28) - 1;
inline constexpr int kTypeImpl83NamespaceShift = 28;

inline constexpr size_t kTypeImplNumMemberMethods = 0x18;

// REMethodDefinition field offsets.
inline constexpr size_t kMethodImplIdDword = 0x4; // impl_id:19 in the low bits
inline constexpr uint32_t kMethodImplIdMask = (1u << 19) - 1;
inline constexpr size_t kMethodEncodedOffset = 0x8;

inline constexpr size_t kMethodImplNameOffset = 0x8;

// (next power of two >= poolSize) - 1, matching RETypeDB::get_string_pool_bitmask()
// upstream:  uint32_t out{1}; while (out < size) out <<= 1; return out - 1;
inline uint32_t StringPoolBitmask(uint32_t poolSize) noexcept
{
    if (poolSize == 0)
    {
        return 0;
    }
    uint32_t out = 1;
    while (out < poolSize)
    {
        if (out > (0xFFFFFFFFu >> 1))
        {
            return 0xFFFFFFFFu;
        }
        out <<= 1;
    }
    return out - 1;
}
} // namespace reengine::re_tdb
