-- Define the protocol fields
local ESesM = Proto("ESesM", "MIAX ESesM Protocol")
local f = ESesM.fields
f.packet_type = ProtoField.string("ESesM.packet_type", "Packet Type", base.ASCII)


local e_unexpected_packet_type = ProtoExpert.new("ESesM.unexpected_packet_type.expert", "Unexpected packet type", expert.group.UNDECODED, expert.severity.ERROR)
local e_packet_too_short = ProtoExpert.new("ESesM.packet_too_short.expert", "Packet is too short", expert.group.MALFORMED, expert.severity.ERROR)
local e_info_message = ProtoExpert.new("ESesM.info_message.expert", "Informational message", expert.group.SEQUENCE, expert.severity.NOTE)
ESesM.experts = { e_unexpected_packet_type, e_packet_too_short, e_info_message }


-- Function to process New Order (N1)
local function process_new_order(buffer, subtree)
    subtree:add_proto_expert_info(e_info_message, "N1 New order")
end

-- Function to process New Order Response (NR)
local function process_new_order_response(buffer, subtree)
    subtree:add_proto_expert_info(e_info_message, "NR New order response")
end


-- Function to handle Sequenced packets
local function handle_sequenced_packet(buffer, subtree)
    subtree:add_proto_expert_info(e_info_message, "Sequenced packet")
end

-- Function to handle Unsequenced packets
local function handle_unsequenced_packet(buffer, subtree)
    subtree:add_proto_expert_info(e_info_message, "Unsequenced packet")
    local packet_type = buffer(0,2):string()
    subtree:add(fields.packet_type, buffer(0, 2))

    if packet_type == "N1" then
        process_new_order(buffer, subtree)
    elseif packet_type == "NR" then
        process_new_order_response(buffer, subtree)
    else
        subtree:add_proto_expert_info(e_unexpected_packet_type, "Unexpected unsequenced packet type: " .. packet_type)
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
    local length = buffer(0,2):uint()
    if length < 3 then
        subtree:add_proto_expert_info(e_packet_too_short, "Packet is too short")
        return
    end

    local packet_type = buffer(2,1):string()
    if packet_type == "s" then
        handle_sequenced_packet(buffer, subtree)
    elseif packet_type == "U" then
        handle_unsequenced_packet(buffer, subtree)
    else
        subtree:add_proto_expert_info(e_unexpected_packet_type, "Unknown packet type: " .. packet_type)
    end
end

-- Register the protocol dissector to a specific port
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(40010, ESesM)  -- Register the protocol for port 40010
tcp_dissector_table:add_for_decode_as(ESesM)
