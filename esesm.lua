-- Define the protocol fields
local ESesM = Proto("ESesM", "MIAX ESesM Protocol")
local f = ESesM.fields
f.packet_type = ProtoField.string("ESesM.packet_type", "Packet Type", base.ASCII)


local e_unexpected_packet_type = ProtoExpert.new("ESesM.unexpected_packet_type.expert", "Unexpected packet type", expert.group.UNDECODED, expert.severity.ERROR)
local e_packet_too_short = ProtoExpert.new("ESesM.packet_too_short.expert", "Packet is too short", expert.group.MALFORMED, expert.severity.ERROR)
local e_info_message = ProtoField.string("ESesM.info_text", "Info Text")
ESesM.experts = { e_unexpected_packet_type, e_packet_too_short }
-- ESesM.fields = { e_info_message }



-- Function to process New Order (N1)
local function process_new_order(buffer, subtree)
    subtree:add(e_info_message, "N1 New order")
end

-- Function to process New Order Response (NR)
local function process_new_order_response(buffer, subtree)
    subtree:add(e_info_message, "NR New order response")
end


-- Function to handle Sequenced packets
local function handle_sequenced(buffer, subtree)
    subtree:add(e_info_message, "Sequenced packet")
end

-- Function to handle Unsequenced packets
local function handle_unsequenced(buffer, subtree)
    subtree:add(e_info_message, "Unsequenced packet")
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

local function handle_login(buffer, subtree)
    subtree:add(e_info_message, "Login")
end

local function handle_login_response(buffer, subtree)
    subtree:add(e_info_message, "Login Response")
end

local function handle_synchronization_complete(buffer, subtree)
    subtree:add(e_info_message, "Synchronization_complete")
end

local function handle_retransmission_request(buffer, subtree)
    subtree:add(e_info_message, "Retransmission_request")
end

local function handle_logout(buffer, subtree)
    subtree:add(e_info_message, "Logout")
end

local function handle_goodbye(buffer, subtree)
    subtree:add(e_info_message, "Goodbye")
end

local function handle_session_update(buffer, subtree)
    subtree:add(e_info_message, "Session Update")
end

local function handle_server_heartbeat(buffer, subtree)
    subtree:add(e_info_message, "Server Heartbeat")
end

local function handle_client_heartbeat(buffer, subtree)
    subtree:add(e_info_message, "Client Heartbeat")
end

local function handle_test(buffer, subtree)
    subtree:add(e_info_message, "Test")
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
        handle_sequenced(buffer, subtree)
    elseif packet_type == "U" then
        handle_unsequenced(buffer, subtree)
    elseif packet_type == "l" then
        handle_login(buffer, subtree)
    elseif packet_type == "r" then
        handle_login_response(buffer, subtree)
    elseif packet_type == "c" then
        handle_synchronization_complete(buffer, subtree)
    elseif packet_type == "a" then
        handle_retransmission_request(buffer, subtree)
    elseif packet_type == "X" then
        handle_logout(buffer, subtree)
    elseif packet_type == "G" then
        handle_goodbye(buffer, subtree)
    elseif packet_type == "u" then
        handle_session_update(buffer, subtree)
    elseif packet_type == "0" then
        handle_server_heartbeat(buffer, subtree)
    elseif packet_type == "1" then
        handle_client_heartbeat(buffer, subtree)
    elseif packet_type == "T" then
        handle_test(buffer, subtree)
    else
        subtree:add_proto_expert_info(e_unexpected_packet_type, "Unknown packet type: " .. packet_type)
    end
end

-- Register the protocol dissector to a specific port
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(40010, ESesM)  -- Register the protocol for port 40010
tcp_dissector_table:add_for_decode_as(ESesM)
