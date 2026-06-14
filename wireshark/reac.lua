-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
--
-- Wireshark / tshark dissector for Roland REAC (audio-over-Ethernet, EtherType
-- 0x8819). Generated from the REAC protocol schema in reac-aes67
-- docs/REAC-PROTOCOL.md (reverse-engineered from reacdriver / obs-h8819 /
-- reaccapture — all GPL-3.0). See that doc for field provenance + citations.
--
-- Load:
--   wireshark -X lua_script:reac.lua
--   tshark -X lua_script:reac.lua -r capture.pcap -V
--   tshark -X lua_script:reac.lua -r capture.pcap -T fields \
--          -e reac.type_name -e reac.counter -e reac.checksum_ok
--
-- The buffer this dissector receives is the REAC payload AFTER the 14-byte
-- Ethernet header (the ethertype table strips dst/src/ethertype; the 802.1Q
-- dissector strips any VLAN tag first), i.e. payload offsets:
--   0   counter[2]  (u16 LE, sequence)
--   2   type[2]     (frame type)
--   4   data[32]    (control/handshake; data[31] = checksum)
--   36  audio[1440] (40 ch x 12 samp x 3 B, even/odd interleave)
--   1476 end[2]     (0xC2 0xEA)
-- = 1478 payload bytes (1492-byte L2 frame).

local reac = Proto("reac", "Roland REAC (0x8819)")

local f = {
  counter   = ProtoField.uint16("reac.counter",   "Sequence counter", base.DEC),
  ftype     = ProtoField.uint16("reac.type",       "Frame type",       base.HEX),
  type_name = ProtoField.string("reac.type_name",  "Frame type name"),
  data      = ProtoField.bytes ("reac.data",       "Control/handshake data[32]"),
  subtype   = ProtoField.string("reac.control.subtype", "CONTROL sub-type"),
  cksum     = ProtoField.uint8 ("reac.checksum",   "Checksum byte (data[31])", base.HEX),
  cksum_ok  = ProtoField.bool  ("reac.checksum_ok","Checksum valid"),
  ma_disc   = ProtoField.uint8 ("reac.master.disc","Announce discriminator (data[6])", base.HEX),
  ma_mac    = ProtoField.ether ("reac.master.mac", "Master MAC (data[9..14])"),
  ma_in     = ProtoField.uint8 ("reac.master.in_channels",  "Master in-channels (data[15])"),
  ma_out    = ProtoField.uint8 ("reac.master.out_channels", "Master out-channels (data[16])"),
  audio     = ProtoField.bytes ("reac.audio",      "Audio (40 ch x 12 samp x 3 B)"),
  endmark   = ProtoField.uint16("reac.end",        "End marker", base.HEX),
}
reac.fields = {}
for _, v in pairs(f) do table.insert(reac.fields, v) end

local e_cksum = ProtoExpert.new("reac.checksum.bad", "REAC header checksum invalid",
                                expert.group.CHECKSUM, expert.severity.WARN)
local e_end   = ProtoExpert.new("reac.end.bad", "REAC end marker is not 0xC2EA",
                                expert.group.MALFORMED, expert.severity.WARN)
reac.experts = { e_cksum, e_end }

-- type[2] registry (reacdriver STREAM_TYPE_IDENTIFIERS)
local TYPE_NAMES = {
  [0x0000] = "FILLER (carries audio; no checksum)",
  [0xcdea] = "CONTROL",
  [0xcfea] = "MASTER_ANNOUNCE",
  [0xceea] = "SPLIT_ANNOUNCE",
}

-- CONTROL sub-type signatures: data[0..4] (reacdriver REAC_STREAM_CONTROL_PACKET_TYPE)
local CONTROL_SUBTYPES = {
  ["0100001a00"] = "CONTROL_ONE",     ["0102000e00"] = "CONTROL_TWO",
  ["0103001901"] = "CONTROL_THREE",   ["0101001800"] = "CONTROL_FOUR",
  ["0103001082"] = "SLAVE_ANNOUNCE1", ["0403001400"] = "SLAVE_ANNOUNCE2",
  ["0403001300"] = "SLAVE_ANNOUNCE3", ["0103000181"] = "SLAVE_ANNOUNCE4",
}

function reac.dissector(tvb, pinfo, tree)
  local len = tvb:len()
  if len < 38 then return 0 end                 -- min: 36 header + 2 end marker
  pinfo.cols.protocol = "REAC"
  local st = tree:add(reac, tvb(), "Roland REAC")

  local counter = tvb(0, 2):le_uint()
  st:add_le(f.counter, tvb(0, 2))

  local typ = tvb(2, 2):uint()                   -- byte0<<8 | byte1 (e.g. 0xCFEA)
  st:add(f.ftype, tvb(2, 2))
  local tname = TYPE_NAMES[typ] or "UNKNOWN (audio?)"
  st:add(f.type_name, tvb(2, 2), tname)

  if len >= 36 then
    local dt = st:add(f.data, tvb(4, 32))
    local sum = 0
    for i = 4, 35 do sum = (sum + tvb(i, 1):uint()) % 256 end
    dt:add(f.cksum, tvb(35, 1))
    local ok = (sum == 0)
    dt:add(f.cksum_ok, tvb(35, 1), ok)
    if typ ~= 0x0000 and not ok then dt:add_proto_expert_info(e_cksum) end

    if typ == 0xcfea then                        -- MASTER_ANNOUNCE overlay
      local ma = dt:add(tvb(4, 32), "MasterAnnouncePacket")
      ma:add(f.ma_disc, tvb(4 + 6, 1))
      ma:add(f.ma_mac,  tvb(4 + 9, 6))
      ma:add(f.ma_in,   tvb(4 + 15, 1))
      ma:add(f.ma_out,  tvb(4 + 16, 1))
    elseif typ == 0xcdea then                    -- CONTROL sub-type
      local sig = tvb(4, 5):bytes():tohex(true)
      st:add(f.subtype, tvb(4, 5), CONTROL_SUBTYPES[sig] or ("unknown (" .. sig .. ")"))
    end
  end

  if len >= 36 + 1440 then st:add(f.audio, tvb(36, 1440)) end

  local em = tvb(len - 2, 2):uint()
  st:add(f.endmark, tvb(len - 2, 2))
  if em ~= 0xc2ea then st:add_proto_expert_info(e_end) end

  pinfo.cols.info = string.format("REAC %s seq=%d", tname:match("^%S+"), counter)
  return len
end

DissectorTable.get("ethertype"):add(0x8819, reac)
