-- SPDX-License-Identifier: GPL-3.0-or-later
-- Copyright (C) 2026 Pau Aliagas <linuxnow@gmail.com>
--
-- Wireshark / tshark dissector for Roland REAC (audio-over-Ethernet, EtherType
-- 0x8819).
--
-- The CONTROL decode below is derived from the STAGEBOX FIRMWARE, not from the
-- reacdriver guesses this file used to carry. See reac-protocol
-- spec/reac.ksy + spec/protocol-facts.yaml for the same grammar in
-- machine-readable form, with the firmware addresses as provenance.
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
--
-- THE CONTROL RECORD HEADER, from the firmware that builds it:
--
--   data[0]   class     0x01 session/scene, 0x04 parameter (DT1 container)
--   data[1]   fragment  bit0 FIRST, bit1 LAST  (so 3 = a whole record in
--                       one frame, 1 = opening, 0 = middle, 2 = closing)
--   data[2:4] rec_len   u16 BIG-ENDIAN, the record byte count counted from
--                       data[4] INCLUSIVE
--   data[4]   subtype   what the record is; bit7 set = a box->master reply
--
-- S-1608 firmware S-1608.BIN (SH-2 LE, load base 0x0BFE0000):
--   FUN_0c003398  scene sender      -- writes the fragment bits and rec_len
--   FUN_0c002f7a  rec_len writer    -- a big-endian u16 store, hence BE
--   FUN_0c002c70  channel map       -- class 01, frag 3, rec_len 0x19, sub 01
--   FUN_0c003c8a  state-4 COMMIT    -- class 01, frag 3, rec_len 0x10, sub 0x82
--   FUN_0c003fe2  link-check ack    -- class 01, frag 3, rec_len 0x01, sub 0x81
--   FUN_0c002e94  chanmap ingest    -- gates data[0]==1, data[1]==3, data[4]==1
--
-- WHAT THIS REPLACES, and why the old table could not be repaired in place.
-- Until 2026-08-23 this file matched a five-byte STRING data[0..4] against a
-- table inherited from the reacdriver project, whose names were guesses:
--
--   0100001a00 CONTROL_ONE      0102000e00 CONTROL_TWO
--   0103001901 CONTROL_THREE    0101001800 CONTROL_FOUR
--   0103001082 SLAVE_ANNOUNCE1  0403001400 SLAVE_ANNOUNCE2
--   0403001300 SLAVE_ANNOUNCE3  0103000181 SLAVE_ANNOUNCE4
--
-- Every one of those five-byte strings is a class, a fragment flag, a LENGTH
-- and a subtype run together. Two consequences, both live defects:
--
--   * The names are wrong. `0103001082` is not a slave announce: it is the
--     box's state-4 COMMIT REPORT, built by FUN_0c003c8a after the master's
--     scene transfer completes, carrying the box's 12-cell I/O inventory.
--     `0103000181` is the box's link-check ack from FUN_0c003fe2, and
--     `0100/0101/0102/0103` are one record class under four fragment flags.
--   * Keying on a length makes the match model-specific. An S-0808 and an
--     S-4000S send the same commit report with subtype 0x84, so `0103001084`
--     fell through the old table as "unknown" while the identical S-1608
--     record was labelled. A chanmap window shorter than eight entries would
--     have done the same.
--
-- Decoding the four header fields separately fixes both at once.

local reac = Proto("reac", "Roland REAC (0x8819)")

local CLASS_NAMES = {
  [0x01] = "session",     -- scene transfer, channel map, commit, heartbeat
  [0x04] = "parameter",   -- DT1 container: head-amp, identity, join grant
}

-- data[4], per class. bit7 set = a reply travelling box -> master.
local SUBTYPE_NAMES = {
  [0x01] = {
    [0x00] = "SCENE",              -- fragment of the master's scene blob
    [0x01] = "CHANNEL_MAP",        -- rotating 8-entry window over 48 slots + 0xfe
    [0x10] = "ENROLL_GROUP_MAP",   -- master's prepare-to-grant, once pre-grant
    [0x80] = "COMMIT_REPORT",      -- box state-4 commit, unlinked arm (S-1608)
    [0x81] = "LINK_ACK",           -- box link-check ack / heartbeat
    [0x82] = "COMMIT_REPORT",      -- box state-4 commit, linked arm (S-1608)
    [0x83] = "COMMIT_REPORT",      -- box state-4 commit, unlinked arm (S-4000S)
    [0x84] = "COMMIT_REPORT",      -- box state-4 commit (S-0808, S-4000S)
  },
  [0x04] = {
    [0x00] = "DT1",                -- head-amp and friends, see reg_page
  },
}

local INVENTORY_CELL = { [0x01] = "output", [0x02] = "analog input", [0x03] = "absent" }

local f = {
  counter   = ProtoField.uint16("reac.counter",   "Sequence counter", base.DEC),
  ftype     = ProtoField.uint16("reac.type",       "Frame type",       base.HEX),
  type_name = ProtoField.string("reac.type_name",  "Frame type name"),
  data      = ProtoField.bytes ("reac.data",       "Control/handshake data[32]"),
  cksum     = ProtoField.uint8 ("reac.checksum",   "Checksum byte (data[31])", base.HEX),
  cksum_ok  = ProtoField.bool  ("reac.checksum_ok","Checksum valid"),

  c_class   = ProtoField.uint8 ("reac.control.class",     "Record class", base.HEX),
  c_class_n = ProtoField.string("reac.control.class_name","Record class name"),
  c_frag    = ProtoField.uint8 ("reac.control.frag",      "Fragment flags", base.HEX),
  c_first   = ProtoField.bool  ("reac.control.first",     "First fragment"),
  c_last    = ProtoField.bool  ("reac.control.last",      "Last fragment"),
  c_len     = ProtoField.uint16("reac.control.rec_len",   "Record length (from data[4])", base.DEC),
  c_sub     = ProtoField.uint8 ("reac.control.subtype",   "Subtype", base.HEX),
  c_sub_n   = ProtoField.string("reac.control.subtype_name","Subtype name"),
  c_reply   = ProtoField.bool  ("reac.control.is_reply",  "Reply (box -> master)"),

  cm_slot   = ProtoField.uint8 ("reac.chanmap.slot",  "Slot", base.HEX),
  cm_cell   = ProtoField.uint8 ("reac.chanmap.cell",  "Inventory cell (high nibble)", base.HEX),
  cm_flags  = ProtoField.uint8 ("reac.chanmap.flags", "Slot flags (low nibble)", base.HEX),
  cm_sens   = ProtoField.uint8 ("reac.chanmap.sens",  "SENS step", base.DEC),

  ci_sel    = ProtoField.uint8 ("reac.commit.selector",  "Selector", base.HEX),
  ci_board  = ProtoField.uint8 ("reac.commit.board_code","Board configuration code", base.DEC),
  ci_cell   = ProtoField.uint8 ("reac.commit.cell",      "Inventory cell", base.HEX),
  ci_in     = ProtoField.uint8 ("reac.commit.in_channels",  "Declared input channels", base.DEC),
  ci_out    = ProtoField.uint8 ("reac.commit.out_channels", "Declared output channels", base.DEC),

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

-- type[2] registry
local TYPE_NAMES = {
  [0x0000] = "FILLER (carries audio; no checksum)",
  [0xcdea] = "CONTROL",
  [0xcfea] = "MASTER_ANNOUNCE",
  [0xceea] = "SPLIT_ANNOUNCE",
}

-- The channel map, class 01 subtype 01. Three bytes a slot: the slot number,
-- a byte whose HIGH nibble is the inventory cell for the group this slot
-- anchors and whose low nibble is three per-slot flags, and the SENS step.
-- Only slots with (slot & 3) == 0 anchor a group -- S-1608 FUN_0c002d42
-- consumes the high nibble there and nowhere else. 0xfe marks the ring wrap.
local function dissect_chanmap(dt, tvb, base_off, reclen)
  local body = dt:add(tvb(base_off, math.min(reclen - 1, 32 - 5)), "Channel map window")
  local off = base_off
  local last = base_off + reclen - 1
  while off + 3 <= last do
    local slot  = tvb(off, 1):uint()
    local flags = tvb(off + 1, 1):uint()
    local sens  = tvb(off + 2, 1):uint()
    local label
    if slot == 0xfe then
      label = "ring wrap marker"
    else
      local cell = INVENTORY_CELL[bit.rshift(flags, 4)] or "?"
      if bit.band(slot, 3) == 0 then
        label = string.format("slot 0x%02x  group %d anchor, cell %s  sens %d",
                              slot, bit.rshift(slot, 2), cell, sens)
      else
        label = string.format("slot 0x%02x  sens %d", slot, sens)
      end
    end
    local e = body:add(tvb(off, 3), label)
    e:add(f.cm_slot,  tvb(off, 1))
    e:add(f.cm_cell,  tvb(off + 1, 1), bit.rshift(flags, 4))
    e:add(f.cm_flags, tvb(off + 1, 1), bit.band(flags, 0x0f))
    e:add(f.cm_sens,  tvb(off + 2, 1))
    off = off + 3
  end
end

-- The state-4 commit report, class 01 subtype 0x8x. Built by S-1608
-- FUN_0c003c8a / S-4000 the same shape: selector, two zero bytes, a board
-- configuration code, then 12 inventory cells of 4 channels each.
local function dissect_commit(dt, tvb, base_off)
  local body = dt:add(tvb(base_off - 1, 16), "Commit report (state-4)")
  body:add(f.ci_sel,   tvb(base_off - 1, 1))
  body:add(f.ci_board, tvb(base_off + 2, 1))
  local nin, nout = 0, 0
  local cells = body:add(tvb(base_off + 3, 12), "Inventory, 12 cells of 4 channels")
  for i = 0, 11 do
    local v = tvb(base_off + 3 + i, 1):uint()
    if v == 2 then nin = nin + 4 elseif v == 1 then nout = nout + 4 end
    local e = cells:add(tvb(base_off + 3 + i, 1),
                        string.format("cell %2d  ch %2d..%2d  %s",
                                      i, i * 4, i * 4 + 3, INVENTORY_CELL[v] or "?"))
    e:add(f.ci_cell, tvb(base_off + 3 + i, 1))
  end
  body:add(f.ci_in,  tvb(base_off + 3, 12), nin):set_generated()
  body:add(f.ci_out, tvb(base_off + 3, 12), nout):set_generated()
  return nin, nout
end

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

  local info = string.format("REAC %s seq=%d", tname:match("^%S+"), counter)

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

    elseif typ == 0xcdea then                    -- CONTROL record header
      local cls    = tvb(4, 1):uint()
      local frag   = tvb(5, 1):uint()
      local reclen = tvb(6, 2):uint()            -- big-endian, from data[4]
      local sub    = tvb(8, 1):uint()

      local hd = dt:add(tvb(4, 5), "Control record header")
      hd:add(f.c_class,   tvb(4, 1))
      hd:add(f.c_class_n, tvb(4, 1), CLASS_NAMES[cls] or "unknown")
      hd:add(f.c_frag,    tvb(5, 1))
      hd:add(f.c_first,   tvb(5, 1), bit.band(frag, 1) ~= 0)
      hd:add(f.c_last,    tvb(5, 1), bit.band(frag, 2) ~= 0)
      hd:add(f.c_len,     tvb(6, 2))
      hd:add(f.c_sub,     tvb(8, 1))
      hd:add(f.c_reply,   tvb(8, 1), bit.band(sub, 0x80) ~= 0)

      local sname = (SUBTYPE_NAMES[cls] or {})[sub]
      if sname == nil then
        sname = string.format("unknown (class 0x%02x subtype 0x%02x)", cls, sub)
      end
      hd:add(f.c_sub_n, tvb(8, 1), sname)

      local fragname = ({ [0] = "middle", [1] = "first", [2] = "last", [3] = "whole" })[frag]
                       or string.format("0x%02x", frag)

      if reclen >= 1 and 9 + reclen - 1 <= 36 then
        if cls == 0x01 and sub == 0x01 then
          dissect_chanmap(dt, tvb, 9, reclen)
        elseif cls == 0x01 and bit.band(sub, 0xf0) == 0x80 and reclen == 0x10 then
          local nin, nout = dissect_commit(dt, tvb, 9)
          sname = string.format("%s (%d in / %d out)", sname, nin, nout)
        end
      end

      info = string.format("REAC CONTROL %s [%s] len=%d seq=%d",
                           sname, fragname, reclen, counter)
    end
  end

  if len >= 36 + 1440 then st:add(f.audio, tvb(36, 1440)) end

  local em = tvb(len - 2, 2):uint()
  st:add(f.endmark, tvb(len - 2, 2))
  if em ~= 0xc2ea then st:add_proto_expert_info(e_end) end

  pinfo.cols.info = info
  return len
end

DissectorTable.get("ethertype"):add(0x8819, reac)
