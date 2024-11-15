-- Define the protocol fields
local ESesM = Proto("ESesM", "MIAX ESesM Protocol")
local f = ESesM.fields
f.packet_type = ProtoField.string("ESesM.packet_type", "Packet Type", base.ASCII)


local e_unexpected_packet_type = ProtoExpert.new("ESesM.unexpected_packet_type.expert", "Unexpected packet type", expert.group.UNDECODED, expert.severity.ERROR)
local e_packet_too_short = ProtoExpert.new("ESesM.packet_too_short.expert", "Packet is too short", expert.group.MALFORMED, expert.severity.ERROR)
ESesM.experts = { e_unexpected_packet_type, e_packet_too_short }


-- Function to process New Order (N1)
local function process_new_order(buffer, subtree)
    subtree:add(f.new_field1, buffer(2, 4))
    subtree:add(f.new_field2, buffer(6, 2))
end

-- Function to process New Order Response (NR)
local function process_new_order_response(buffer, subtree)
    subtree:add(f.response_field1, buffer(2, 2))
    subtree:add(f.response_field2, buffer(4, 4))
end

-- Function to check and add the packet type
local function check_and_add_packet_type(buffer, subtree, fields)
    local packet_type = buffer(0,2):string()
    subtree:add(fields.packet_type, buffer(0, 2))

    if packet_type == "N1" then
        process_new_order(buffer, subtree)
    elseif packet_type == "NR" then
        process_new_order_response(buffer, subtree)
    else
        subtree:add_proto_expert_info(e_unexpected_packet_type, "Unexpected packet type: " .. packet_type)
        return false -- Indicate error
    end
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
        subtree:add_proto_expert_info(e_packet_too_short, "Packet is too short")
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
