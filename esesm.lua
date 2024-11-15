-- Define the protocol fields
local ESesM = Proto("ESesM", "MIAX ESesM Protocol")
local f = ESesM.fields
f.packet_type = ProtoField.string("ESesM.packet_type", "Packet Type", base.ASCII)

-- Function to check and add the packet type
local function check_and_add_packet_type(buffer, subtree, fields)
    local packet_type = buffer(0,2):string()
    if packet_type ~= "N1" then
        subtree:add_proto_expert_info(PI_UNDECODED, PI_ERROR, "Unexpected packet type: " .. packet_type)
        subtree:add(fields.packet_type, buffer(0, 2))
        return false -- Indicate error
    end
    -- Add the packet type to the subtree as normal
    subtree:add(fields.packet_type, buffer(0, 2))
    return true -- Indicate success
end

-- Dissector function
function ESesM.dissector(buffer, pinfo, tree)
    -- Set protocol name in the packet list
    pinfo.cols.protocol = "ESesM"

    -- Add protocol details to the tree
    local subtree = tree:add(ESesM, buffer(), "MIAX ESesM Protocol Data")

    -- Ensure there's enough data
    if buffer:len() < 2 then
        subtree:add_proto_expert_info(PI_MALFORMED, PI_ERROR, "Packet is too short")
        return
    end

    if not check_and_add_packet_type(buffer, subtree, f) then
        return
    end
end

-- Register the protocol dissector to a specific port
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(40010, ESesM)  -- Register the protocol for port 40010
tcp_dissector_table:add_for_decode_as(ESesM)
