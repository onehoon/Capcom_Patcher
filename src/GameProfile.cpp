#include "pch.h"

#include "GameProfile.h"

#include "Util.h"

#include <algorithm>
#include <array>
#include <cwctype>

namespace game_profile
{
namespace
{
struct Entry
{
    const wchar_t* executable; // lower-case release executable name
    GameProfile profile;
};

// Explicit six-game capability matrix (see the architecture plan, section 7,
// and the PR0 work order, section 4.2). No inheritance from TDB version.
constexpr std::array<Entry, 6> kEntries{{
    {L"monsterhunterwilds.exe",
     {GameId::MonsterHunterWilds, L"Monster Hunter Wilds",
      /*dbgUi*/ true, /*dd2*/ true, /*re9*/ false, /*re9SlowPath*/ false, /*heartbeat*/ false}},
    {L"dd2.exe",
     {GameId::DragonsDogma2, L"Dragon's Dogma 2",
      true, true, true, false, true}},
    {L"re9.exe",
     {GameId::ResidentEvilRequiem, L"Resident Evil Requiem",
      true, true, true, true, true}},
    {L"pragmata.exe",
     {GameId::Pragmata, L"PRAGMATA",
      true, true, true, false, true}},
    {L"onimushawots.exe",
     {GameId::OnimushaWots, L"Onimusha: Way of the Sword",
      true, true, true, false, true}},
    {L"monster_hunter_stories_3_twisted_reflection.exe",
     {GameId::MonsterHunterStories3, L"Monster Hunter Stories 3: Twisted Reflection",
      true, true, true, false, true}},
}};

std::wstring ToLower(std::wstring_view value)
{
    std::wstring lowered(value);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return lowered;
}
} // namespace

GameProfile Resolve(std::wstring_view executableFileName)
{
    const std::wstring name = ToLower(executableFileName);
    for (const auto& entry : kEntries)
    {
        if (name == entry.executable)
        {
            return entry.profile;
        }
    }
    return GameProfile{};
}

const GameProfile& Current()
{
    static const GameProfile profile = Resolve(Util::ExePath().filename().wstring());
    return profile;
}
} // namespace game_profile
