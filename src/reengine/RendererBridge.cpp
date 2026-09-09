#include "pch.h"

#include "RendererBridge.h"

#include "MinimalReTdb.h"
#include "../memory/MemoryScan.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <iterator>

// VM context / TDB discovery and the type/method/singleton resolution below are
// behaviorally adapted from praydog/REFramework @ b6baf6b (MIT). See
// RendererBridge.h and THIRD_PARTY_NOTICES.md.

namespace reengine
{
namespace
{
void Log(const char* format, ...)
{
    char buffer[512]{};
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
}

template <class T>
bool ReadT(uintptr_t address, T& out) noexcept
{
    return memory::TryReadBytes(address, &out, sizeof(T));
}

bool IsExecutable(uintptr_t address) noexcept
{
    if (address == 0)
    {
        return false;
    }
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
    {
        return false;
    }
    if (mbi.State != MEM_COMMIT)
    {
        return false;
    }
    const DWORD prot = mbi.Protect & 0xFFu;
    return prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
           prot == PAGE_EXECUTE_WRITECOPY;
}

// All hits of `pattern` in [start, start+length).
template <class Fn>
void ForEachMatch(uintptr_t start, size_t length, std::string_view pattern, Fn&& fn)
{
    uintptr_t cursor = start;
    const uintptr_t end = start + length;
    while (cursor < end)
    {
        const auto hit = memory::Scan(cursor, end - cursor, pattern);
        if (!hit)
        {
            return;
        }
        if (!fn(*hit))
        {
            return;
        }
        cursor = *hit + 1;
    }
}

// REFramework REMethodDefinition::get_function() encoded-pointer base:
//   85 C9 75 03 33 C0 C3 48 63 C1 48 8D 0D ?? ?? ?? ?? 48 03 C1 C3
//   test ecx,ecx / jnz +3 / xor eax,eax / ret / movsxd rax,ecx /
//   lea rcx,[rip+disp32] / add rax,rcx / ret
// The lea displacement (at hit+13) resolves to the function-table base; an
// encoded method offset is added to it.
uintptr_t FindEncodedFunctionBase(const memory::ModuleRange& mod) noexcept
{
    static uintptr_t cached = 0;
    static bool tried = false;
    if (tried)
    {
        return cached;
    }
    tried = true;

    const auto hit = memory::Scan(mod, "85 C9 75 03 33 C0 C3 48 63 C1 48 8d 0D ? ? ? ? 48 03 C1 C3");
    if (!hit)
    {
        Log("[CapcomPatcher][Heartbeat][Bridge] encoded-pointer base pattern not found");
        return 0;
    }

    const uintptr_t base = memory::CalculateAbsolute(*hit + 13, 4);
    if (base < mod.base || base >= mod.end())
    {
        Log("[CapcomPatcher][Heartbeat][Bridge] encoded-pointer base out of module range");
        return 0;
    }
    cached = base;
    Log("[CapcomPatcher][Heartbeat][Bridge] encoded_function_base @ 0x%p", reinterpret_cast<void*>(base));
    return cached;
}

// Read a string-pool entry as a NUL-terminated C string into `out`.
bool ReadPoolString(uintptr_t stringPool, uint32_t poolSize, uint32_t rawOffset, char* out, size_t outSize) noexcept
{
    const uint32_t offset = rawOffset & re_tdb::StringPoolBitmask(poolSize);
    if (offset >= poolSize)
    {
        return false;
    }
    const uintptr_t address = stringPool + offset;
    for (size_t i = 0; i < outSize - 1; ++i)
    {
        char ch = 0;
        if (!memory::TryReadBytes(address + i, &ch, 1))
        {
            return false;
        }
        out[i] = ch;
        if (ch == '\0')
        {
            return true;
        }
    }
    out[outSize - 1] = '\0';
    return true;
}
} // namespace

std::optional<uint32_t> ExpectedTdbVersion(game_profile::GameId id) noexcept
{
    using game_profile::GameId;
    switch (id)
    {
    case GameId::DragonsDogma2:
    case GameId::ResidentEvilRequiem:
    case GameId::Pragmata:
        return 83u;
    case GameId::OnimushaWots:
    case GameId::MonsterHunterStories3:
        return 82u;
    case GameId::MonsterHunterWilds:
    case GameId::Unsupported:
    default:
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------

bool RendererBridge::ResolveVmContext() noexcept
{
    if (m_globalContextSlot != nullptr)
    {
        return true;
    }

    const auto mod = memory::MainModule();
    if (!mod)
    {
        return false;
    }

    // REContext.cpp: count references to the same resolved context pointer;
    // > 10 identical resolutions is "for sure the right one".
    struct Ref
    {
        uintptr_t value{};
        uint32_t count{};
    };
    Ref refs[64]{};
    size_t refCount = 0;
    uintptr_t winner = 0;
    uintptr_t winnerHit = 0;

    ForEachMatch(mod.base, mod.size, "48 8B 0D ? ? ? ? BA FF FF FF FF E8 ? ? ? ?", [&](uintptr_t hit) {
        // Validate the candidate really decodes as `mov r64, [rip+disp32]`.
        const auto decoded = memory::DecodeOne(hit);
        if (!decoded || decoded->length != 7)
        {
            return true;
        }

        const uintptr_t ctxRef = memory::CalculateAbsolute(hit + 3, 4);
        if (ctxRef < mod.base || ctxRef >= mod.end())
        {
            return true;
        }

        for (size_t i = 0; i < refCount; ++i)
        {
            if (refs[i].value == ctxRef)
            {
                if (++refs[i].count > 10)
                {
                    winner = ctxRef;
                    winnerHit = hit;
                    return false;
                }
                return true;
            }
        }
        if (refCount < std::size(refs))
        {
            refs[refCount++] = Ref{ctxRef, 1};
        }
        return true;
    });

    if (winner == 0)
    {
        return false;
    }

    // ctx_offset for this pattern is 3 (same field the reference count keyed on).
    auto* slot = reinterpret_cast<void**>(memory::CalculateAbsolute(winnerHit + 3, 4));
    void* contextObj = nullptr;
    if (!ReadT(reinterpret_cast<uintptr_t>(slot), contextObj) || contextObj == nullptr)
    {
        return false;
    }

    m_globalContextSlot = slot;
    ++m_counters.vmContextResolved;
    Log("[CapcomPatcher][Heartbeat][Bridge] VM context resolved");
    return true;
}

bool RendererBridge::ResolveTdb() noexcept
{
    if (m_tdb != 0)
    {
        return true;
    }
    if (m_globalContextSlot == nullptr)
    {
        return false;
    }

    void* contextObj = nullptr;
    if (!ReadT(reinterpret_cast<uintptr_t>(m_globalContextSlot), contextObj) || contextObj == nullptr)
    {
        return false;
    }

    const uintptr_t contextBase = reinterpret_cast<uintptr_t>(contextObj);
    for (size_t i = 0; i < 0x20000; i += sizeof(void*))
    {
        uintptr_t candidate = 0;
        if (!ReadT(contextBase + i, candidate) || candidate == 0)
        {
            continue;
        }
        if ((candidate & (sizeof(void*) - 1)) != 0 || !memory::IsReadable(candidate, 8))
        {
            continue;
        }

        uint32_t magic = 0;
        if (!ReadT(candidate + re_tdb::kTdbMagic, magic) || magic != re_tdb::kTdbMagicValue)
        {
            continue;
        }

        uint32_t version = 0;
        if (!ReadT(candidate + re_tdb::kTdbVersion, version))
        {
            continue;
        }

        if (version != m_expectedTdbVersion)
        {
            m_layoutUnsupported = true;
            Log("[CapcomPatcher][Heartbeat][Bridge] expected TDB%u, observed TDB%u; disabled for this session",
                m_expectedTdbVersion, version);
            return false;
        }

        m_tdb = candidate;
        m_tdbVersion = version;
        ++m_counters.tdbValidated;
        Log("[CapcomPatcher][Heartbeat][Bridge] TDB%u validated", version);
        return true;
    }

    return false;
}

bool RendererBridge::ResolveRendererType() noexcept
{
    if (m_rendererType != 0)
    {
        return true;
    }
    if (m_tdb == 0)
    {
        return false;
    }

    uint32_t numTypes = 0;
    uintptr_t typesPtr = 0;
    uintptr_t typesImplPtr = 0;
    uint32_t poolSize = 0;
    uintptr_t stringPool = 0;
    if (!ReadT(m_tdb + re_tdb::kTdbNumTypes, numTypes) || !ReadT(m_tdb + re_tdb::kTdbTypesPtr, typesPtr) ||
        !ReadT(m_tdb + re_tdb::kTdbTypesImplPtr, typesImplPtr) ||
        !ReadT(m_tdb + re_tdb::kTdbNumStringPool, poolSize) ||
        !ReadT(m_tdb + re_tdb::kTdbStringPoolPtr, stringPool))
    {
        return false;
    }
    if (numTypes == 0 || numTypes > 0x100000 || typesPtr == 0 || typesImplPtr == 0 || stringPool == 0)
    {
        return false;
    }

    const bool tdb83 = (m_tdbVersion == 83);

    for (uint32_t i = 0; i < numTypes; ++i)
    {
        const uintptr_t typeDef = typesPtr + static_cast<size_t>(i) * re_tdb::kTypeDefStride;

        uint64_t q1 = 0;
        if (!ReadT(typeDef + re_tdb::kTypeDefQword1, q1))
        {
            continue;
        }
        const uint32_t implIndex =
            static_cast<uint32_t>((q1 >> re_tdb::kImplIndexShift) & re_tdb::kImplIndexMask);

        const uintptr_t impl = typesImplPtr + static_cast<size_t>(implIndex) * re_tdb::kTypeImplStride;

        uint32_t nameRaw = 0;
        uint32_t namespaceRaw = 0;
        if (tdb83)
        {
            uint64_t packed = 0;
            if (!ReadT(impl, packed))
            {
                continue;
            }
            nameRaw = static_cast<uint32_t>(packed & re_tdb::kTypeImpl83OffsetMask);
            namespaceRaw = static_cast<uint32_t>((packed >> re_tdb::kTypeImpl83NamespaceShift) &
                                                 re_tdb::kTypeImpl83OffsetMask);
        }
        else
        {
            if (!ReadT(impl + re_tdb::kTypeImpl82NameOffset, nameRaw) ||
                !ReadT(impl + re_tdb::kTypeImpl82NamespaceOffset, namespaceRaw))
            {
                continue;
            }
        }

        char name[64]{};
        if (!ReadPoolString(stringPool, poolSize, nameRaw, name, sizeof(name)) ||
            std::strcmp(name, "Renderer") != 0)
        {
            continue;
        }

        char ns[64]{};
        if (!ReadPoolString(stringPool, poolSize, namespaceRaw, ns, sizeof(ns)) ||
            std::strcmp(ns, "via.render") != 0)
        {
            continue;
        }

        void* typeClr = nullptr;
        if (!ReadT(typeDef + re_tdb::kTypeDefTypePtr, typeClr) || typeClr == nullptr ||
            !memory::IsReadable(reinterpret_cast<uintptr_t>(typeClr), sizeof(void*)))
        {
            Log("[CapcomPatcher][Heartbeat][Bridge] via.render.Renderer found but REType pointer invalid");
            return false;
        }

        m_rendererType = typeDef;
        m_rendererTypeClr = typeClr;
        ++m_counters.rendererTypeResolved;
        Log("[CapcomPatcher][Heartbeat][Bridge] via.render.Renderer resolved (type index %u)", i);
        return true;
    }

    return false;
}

bool RendererBridge::ResolveGetRenderFrame() noexcept
{
    if (m_getRenderFrame != nullptr)
    {
        return true;
    }
    if (m_rendererType == 0)
    {
        return false;
    }

    const auto mod = memory::MainModule();
    if (!mod)
    {
        return false;
    }

    uintptr_t methodsPtr = 0;
    uintptr_t methodsImplPtr = 0;
    uintptr_t typesImplPtr = 0;
    uint32_t numMethods = 0;
    uint32_t poolSize = 0;
    uintptr_t stringPool = 0;
    if (!ReadT(m_tdb + re_tdb::kTdbMethodsPtr, methodsPtr) ||
        !ReadT(m_tdb + re_tdb::kTdbMethodsImplPtr, methodsImplPtr) ||
        !ReadT(m_tdb + re_tdb::kTdbTypesImplPtr, typesImplPtr) ||
        !ReadT(m_tdb + re_tdb::kTdbNumMethods, numMethods) ||
        !ReadT(m_tdb + re_tdb::kTdbNumStringPool, poolSize) ||
        !ReadT(m_tdb + re_tdb::kTdbStringPoolPtr, stringPool) || methodsPtr == 0 || methodsImplPtr == 0)
    {
        return false;
    }

    uint64_t q1 = 0;
    uint64_t memberQword = 0;
    if (!ReadT(m_rendererType + re_tdb::kTypeDefQword1, q1) ||
        !ReadT(m_rendererType + re_tdb::kTypeDefMemberQword, memberQword))
    {
        return false;
    }
    const uint32_t implIndex = static_cast<uint32_t>((q1 >> re_tdb::kImplIndexShift) & re_tdb::kImplIndexMask);
    const uint32_t memberMethod =
        static_cast<uint32_t>((memberQword >> re_tdb::kMemberMethodShift) & re_tdb::kMemberMethodMask);

    const uintptr_t impl = typesImplPtr + static_cast<size_t>(implIndex) * re_tdb::kTypeImplStride;
    uint16_t numMemberMethods = 0;
    if (!ReadT(impl + re_tdb::kTypeImplNumMemberMethods, numMemberMethods) || numMemberMethods == 0)
    {
        return false;
    }

    const uintptr_t encodedBase = FindEncodedFunctionBase(mod);
    if (encodedBase == 0)
    {
        return false;
    }

    for (uint32_t k = 0; k < numMemberMethods; ++k)
    {
        const uint32_t methodIndex = memberMethod + k;
        if (methodIndex >= numMethods)
        {
            break;
        }
        const uintptr_t method = methodsPtr + static_cast<size_t>(methodIndex) * re_tdb::kMethodStride;

        uint32_t implIdDword = 0;
        int32_t encodedOffset = 0;
        if (!ReadT(method + re_tdb::kMethodImplIdDword, implIdDword) ||
            !ReadT(method + re_tdb::kMethodEncodedOffset, encodedOffset))
        {
            continue;
        }
        if (encodedOffset == 0)
        {
            continue;
        }
        const uint32_t implId = implIdDword & re_tdb::kMethodImplIdMask;
        const uintptr_t methodImpl = methodsImplPtr + static_cast<size_t>(implId) * re_tdb::kMethodImplStride;

        uint32_t nameOffset = 0;
        if (!ReadT(methodImpl + re_tdb::kMethodImplNameOffset, nameOffset))
        {
            continue;
        }

        char name[48]{};
        if (!ReadPoolString(stringPool, poolSize, nameOffset, name, sizeof(name)) ||
            std::strcmp(name, "get_RenderFrame") != 0)
        {
            continue;
        }

        const uintptr_t fn = encodedBase + static_cast<uintptr_t>(static_cast<int64_t>(encodedOffset));
        if (fn < mod.base || fn >= mod.end() || !IsExecutable(fn))
        {
            Log("[CapcomPatcher][Heartbeat][Bridge] get_RenderFrame resolved to a non-executable address");
            return false;
        }

        m_getRenderFrame = reinterpret_cast<GetRenderFrameFn>(fn);
        ++m_counters.getRenderFrameResolved;
        Log("[CapcomPatcher][Heartbeat][Bridge] get_RenderFrame resolved @ 0x%p (module +0x%zx)",
            reinterpret_cast<void*>(fn), static_cast<size_t>(fn - mod.base));
        return true;
    }

    return false;
}

void* RendererBridge::ResolveRendererSingleton() noexcept
{
    if (m_rendererTypeClr == nullptr)
    {
        return nullptr;
    }

    // REType.cpp: f = (*(SingletonFunc**)t)[1]; f(t, &out, nullptr);
    uintptr_t vtable = 0;
    if (!ReadT(reinterpret_cast<uintptr_t>(m_rendererTypeClr), vtable) || vtable == 0 ||
        !memory::IsReadable(vtable, sizeof(void*) * 2))
    {
        return nullptr;
    }
    uintptr_t singletonFn = 0;
    if (!ReadT(vtable + sizeof(void*), singletonFn) || !IsExecutable(singletonFn))
    {
        return nullptr;
    }

    using SingletonFunc = void (*)(void*, void**, void*);
    auto fn = reinterpret_cast<SingletonFunc>(singletonFn);

    void* out = nullptr;
    __try
    {
        fn(m_rendererTypeClr, &out, nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ++m_counters.faults;
        return nullptr;
    }

    if (out == nullptr || !memory::IsReadable(reinterpret_cast<uintptr_t>(out), 0x4000))
    {
        return nullptr;
    }
    return out;
}

ResolveStatus RendererBridge::Resolve(RendererFrameSource& out) noexcept
{
    ++m_counters.resolveAttempts;

    if (m_layoutUnsupported)
    {
        return ResolveStatus::UnsupportedLayout;
    }

    if (!ResolveVmContext())
    {
        return ResolveStatus::NotReadyYet;
    }
    if (!ResolveTdb())
    {
        return m_layoutUnsupported ? ResolveStatus::UnsupportedLayout : ResolveStatus::NotReadyYet;
    }
    if (!ResolveRendererType())
    {
        return ResolveStatus::NotReadyYet;
    }
    if (!ResolveGetRenderFrame())
    {
        return ResolveStatus::NotReadyYet;
    }

    void* renderer = ResolveRendererSingleton();
    if (renderer == nullptr)
    {
        return ResolveStatus::NotReadyYet;
    }
    if (m_counters.singletonResolved == 0)
    {
        Log("[CapcomPatcher][Heartbeat] renderer instance @ 0x%p", renderer);
    }
    ++m_counters.singletonResolved;

    out.renderer = renderer;
    out.getRenderFrame = m_getRenderFrame;
    out.tdbVersion = m_tdbVersion;
    return ResolveStatus::Ready;
}
} // namespace reengine
