-- SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
-- SPDX-License-Identifier: GPL-3.0-only
--
-- Which output a sound card plays to, as the Veil profile's audio_output
-- says (docs/design/wisp.md), through the wisp.audio-output setting that
-- the greeter sets with wpctl:
--
--   display  the monitor's HDMI/DisplayPort audio. Kept while the display
--            sleeps, when the GPU withdraws the monitor's audio (its ELD)
--            and the profile reads as unavailable: WirePlumber's own choice
--            would move to the built-in speaker until it woke, and then
--            stay there, since analog profiles outrank HDMI ones.
--   builtin  the best profile that isn't HDMI: the speaker or audio jack.
--   auto     WirePlumber's own choice.
--
-- Only cards whose outputs are separate profiles (PipeWire's ACP, as on
-- most Intel and AMD HDA); a UCM card's HiFi profile carries every output
-- at once, so this leaves it to WirePlumber.

cutils = require ("common-utils")
log = Log.open_topic ("s-device")

local function is_display (profile)
  return profile.name:find ("hdmi", 1, true) ~= nil
end

local function selectable (profile)
  return profile.name ~= "off" and profile.name ~= "pro-audio"
end

local function find (device, mode)
  local active = nil
  for p in device:iterate_params ("Profile") do
    active = cutils.parseParam (p, "Profile")
  end
  local best = nil
  local current = nil
  for p in device:iterate_params ("EnumProfile") do
    local profile = cutils.parseParam (p, "EnumProfile")
    if profile and selectable (profile) and is_display (profile) == (mode == "display") then
      if profile.available == "yes" and (best == nil or profile.priority > best.priority) then
        best = profile
      end
      if active and profile.index == active.index then
        current = profile
      end
    end
  end
  if best == nil and mode == "display" then
    -- No display is listening, likely asleep: stay on its output rather
    -- than move to the speaker.
    return current
  end
  return best
end

SimpleEventHook {
  name = "wisp/audio-output",
  after = "device/find-stored-profile",
  before = "device/find-preferred-profile",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "select-profile" },
      Constraint { "device.api", "=", "alsa" },
    },
  },
  execute = function (event)
    if event:get_data ("selected-profile") then
      return
    end
    local mode = Settings.get_string ("wisp.audio-output")
    if mode ~= "display" and mode ~= "builtin" then
      return
    end
    local device = event:get_subject ()
    local profile = find (device, mode)
    if profile then
      log:info (device, string.format ("wisp: %s output '%s' (%d) for '%s'",
          mode, profile.name, profile.index, device.properties["device.name"] or ""))
      event:set_data ("selected-profile", profile)
    end
  end
}:register ()

-- A new setting picks again for every card at once.
alsa_devices = ObjectManager {
  Interest {
    type = "device",
    Constraint { "device.api", "=", "alsa" },
  }
}
alsa_devices:activate ()

Settings.subscribe ("wisp.audio-output", function ()
  local source = Plugin.find ("standard-event-source")
  for device in alsa_devices:iterate () do
    source:call ("push-event", "select-profile", device, nil)
  end
end)
