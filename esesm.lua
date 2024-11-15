print("Lua scripting is enabled in Wireshark!")

-- Define the protocol
local ESesM = Proto("ESesM", "MIAX ESesM Protocol")

-- Define the protocol fields
local f = ESesM.fields
f.packet_length = ProtoField.int32("ESesM.packet_length", "Packet Length", base.DEC)
f.packet_type = ProtoField.string("ESesM.packet_type", "Packet Type", base.ASCII)

-- Dissector function
function ESesM.dissector(buffer, pinfo, tree)
    -- Set protocol name in the packet list
    pinfo.cols.protocol = "ESesM"

    -- Add protocol details to the tree
    local subtree = tree:add(ESesM, buffer(), "MIAX ESesM Protocol Data")

    -- Ensure there's enough data
    if buffer:len() < 500000 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet is too short")
        return
    end

    -- Parse fields (example)
    subtree:add(f.packet_length, buffer(0, 4)) -- First 4 bytes: packet length
    subtree:add(f.packet_type, buffer(4, 1)) -- Next byte: packet type
end

-- Register the protocol dissector to a specific port
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(41010, ESesM)

-- Enable "Decode As" functionality
tcp_dissector_table:add_for_decode_as(ESesM)
