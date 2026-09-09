#include "pch.h"

#include "GameProfile.h"

#include "Util.h"

#include <array>

namespace game_profile
{
namespace
{
struct Entry
{
    const wchar_t* executable; // lower-case release executable name (ASCII)
    GameProfile profile;
};

// Explicit six-game capability matrix (see the architecture plan, section 7,
// and the PR0 work order, section 4.2). No inheritance from TDB version.
// This is the single canonical table; both the normal and the loader-lock-safe
// early resolution paths match against it so they cannot drift.
// Fields: dbgUiWatcher, dd2Family, dd2ScannerCrasher, re9Family, re9SlowPath, heartbeat
constexpr std::array<Entry, 6> kEntries{{
    {L"monsterhunterwilds.exe",
     {GameId::MonsterHunterWilds, L"Monster Hunter Wilds",
      true, true, /*dd2ScannerCrasher*/ true, false, false, false}},
    {L"dd2.exe",
     {GameId::DragonsDogma2, L"Dragon's Dogma 2",
      true, true, false, true, false, true}},
    {L"re9.exe",
     {GameId::ResidentEvilRequiem, L"Resident Evil Requiem",
      true, true, false, true, true, true}},
    {L"pragmata.exe",
     {GameId::Pragmata, L"PRAGMATA",
      true, true, false, true, false, true}},
    {L"onimushawots.exe",
     {GameId::OnimushaWots, L"Onimusha: Way of the Sword",
      true, true, false, true, false, true}},
    {L"monster_hunter_stories_3_twisted_reflection.exe",
     {GameId::MonsterHunterStories3, L"Monster Hunter Stories 3: Twisted Reflection",
      true, true, false, true, false, true}},
}};

constexpr wchar_t AsciiToLower(wchar_t ch) noexcept
{
    return (ch >= L'A' && ch <= L'Z') ? static_cast<wchar_t>(ch - L'A' + L'a') : ch;
}

// Allocation-free, ASCII-only case-insensitive compare. `candidate` is one of
// the already-lower-case kEntries keys; `name` is the observed file name.
bool EqualsFold(const wchar_t* name, std::size_t nameLen, const wchar_t* candidate) noexcept
{
    std::size_t i = 0;
    for (; i < nameLen && candidate[i] != L'\0'; ++i)
    {
        if (AsciiToLower(name[i]) != candidate[i])
        {
            return false;
        }
    }
    return i == nameLen && candidate[i] == L'\0';
}

GameId ResolveIdNoAlloc(const wchar_t* fileName) noexcept
{
    std::size_t len = 0;
    while (fileName[len] != L'\0')
    {
        ++len;
    }

    for (const auto& entry : kEntries)
    {
        if (EqualsFold(fileName, len, entry.executable))
        {
            return entry.profile.id;
        }
    }
    return GameId::Unsupported;
}

const GameProfile& ProfileForId(GameId id) noexcept
{
    static constexpr GameProfile kUnsupported{};
    for (const auto& entry : kEntries)
    {
        if (entry.profile.id == id)
        {
            return entry.profile;
        }
    }
    return kUnsupported;
}
} // namespace

GameProfile Resolve(std::wstring_view executableFileName)
{
    return ProfileForId(ResolveIdNoAlloc(std::wstring(executableFileName).c_str()));
}

GameId ResolveCurrentProcessEarly() noexcept
{
    wchar_t path[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    if (length == 0 || length >= ARRAYSIZE(path))
    {
        return GameId::Unsupported;
    }

    const wchar_t* fileName = path;
    for (const wchar_t* p = path; *p != L'\0'; ++p)
    {
        if (*p == L'\\' || *p == L'/')
        {
            fileName = p + 1;
        }
    }

    return ResolveIdNoAlloc(fileName);
}

const GameProfile& Current()
{
    static const GameProfile profile = Resolve(Util::ExePath().filename().wstring());
    return profile;
}
} // namespace game_profile
