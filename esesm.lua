-- Define the protocol fields
local ESesM = Proto("ESesM", "MIAX ESesM")
ESesM.fields.packet_type = ProtoField.string("ESesM.packet_type", "Packet Type", base.ASCII)
ESesM.fields.f_packet_length = ProtoField.uint16("ESesM.packet_length", "Length", base.DEC)

ESesM.fields.f_login = ProtoField.bytes("ESesM.login", "Login")
ESesM.fields.f_login_response = ProtoField.bytes("ESesM.login_response", "Login Response")
ESesM.fields.f_version = ProtoField.string("ESesM.version", "Version")
ESesM.fields.f_username = ProtoField.string("ESesM.username", "Username")
ESesM.fields.f_computer_id = ProtoField.string("ESesM.computer_id", "Computer ID") 
ESesM.fields.f_application_protocol = ProtoField.string("ESesM.application_protocol", "Application protocol") 
ESesM.fields.f_number_of_matching_engines = ProtoField.uint16("ESesM.matching_engines", "Matching Engines") 
ESesM.fields.f_status_code = ProtoField.uint8("ESesM.status_code", "Status Code", base.DEC)
ESesM.fields.f_status_code_ok = ProtoField.uint8("ESesM.status_code", "Status Code OK", base.DEC)

local e_undecoded = ProtoExpert.new("ESesM.unexpected_packet_type.expert", "Unexpected packet type", expert.group.UNDECODED, expert.severity.ERROR)
local e_packet_too_short = ProtoExpert.new("ESesM.packet_too_short.expert", "Packet is too short", expert.group.MALFORMED, expert.severity.ERROR)
local e_info_message = ProtoField.string("ESesM.info_text", "Info Text")

ESesM.experts = { e_undecoded, e_packet_too_short }

-- Function to process New Order (N1)
local function process_new_order(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "N1 New order")
end

-- Function to process New Order Response (NR)
local function process_new_order_response(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "NR New order response")
end


-- Function to handle Sequenced packets
local function handle_sequenced(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Sequenced packet")
end

-- Function to handle Unsequenced packets
local function handle_unsequenced(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Unsequenced packet")
    local packet_type = buffer(0,2):string()
    subtree:add(fields.packet_type, buffer(0, 2))

    if packet_type == "N1" then
        process_new_order(buffer, subtree)
    elseif packet_type == "NR" then
        process_new_order_response(buffer, subtree)
    else
        subtree:add_proto_expert_info(e_undecoded, "Unexpected unsequenced packet type: " .. packet_type)
        return false -- Indicate error
    end
    return true -- Indicate success
end

local function handle_login(buffer, subtree, offset, packet_length)  
    local data = buffer(offset, packet_length-2)
    subtree:add(ESesM.fields.f_login, data)
    offset = offset + 1

    subtree:add(ESesM.fields.f_version, buffer(offset, 5))
    offset = offset + 5
    subtree:add(ESesM.fields.f_username, buffer(offset, 5))
    offset = offset + 5
    subtree:add(ESesM.fields.f_computer_id, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_application_protocol, buffer(offset, 8))    
    offset = offset + 8
    subtree:add_le(ESesM.fields.f_number_of_matching_engines, buffer(offset, 1))    
    offset = offset + 1
end

local function handle_login_response(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-2)
    subtree:add(ESesM.fields.f_login_response, data)
    offset = offset + 1
    subtree:add_le(ESesM.fields.f_number_of_matching_engines, buffer(offset, 1))    
    offset = offset + 1

    local status = buffer(offset,1):string()
    if status == " " then
        subtree:add(ESesM.fields.f_status_code_ok, buffer(offset, 1))
    else
        local item = subtree:add(ESesM.fields.f_status_code, buffer(offset, 1))
        item:add_proto_expert_info(e_undecoded)
    end
    offset = offset + 1
end

local function handle_synchronization_complete(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Synchronization_complete")
end

local function handle_retransmission_request(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Retransmission_request")
end

local function handle_logout(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Logout")
end

local function handle_goodbye(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Goodbye")
end

local function handle_session_update(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Session Update")
end

local function handle_server_heartbeat(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Server Heartbeat")
end

local function handle_client_heartbeat(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Client Heartbeat")
end

local function handle_test(buffer, subtree, offset, packet_length)
    subtree:add(e_info_message, "Test")
end

-- Dissector function
function ESesM.dissector(buffer, pinfo, tree)
    -- Set protocol name in the packet list
    pinfo.cols.protocol = "ESesM"

    -- Add protocol details to the tree
    local subtree = tree:add(ESesM, buffer(), "MIAX ESesM Protocol Data")

    -- Ensure there's enough data
    local length = buffer(0,2):le_uint()
    if length < 3 then
        subtree:add_proto_expert_info(e_packet_too_short, "Packet is too short")
        return
    end

    local offset = 0
    subtree:add_le(ESesM.fields.f_packet_length, buffer(offset, 2))
    local packet_length = buffer(offset, 2):le_uint()
    offset = offset + 2


    local packet_type = buffer(2,1):string()
    if packet_type == "s" then
        handle_sequenced(buffer, subtree, offset, packet_length)
    elseif packet_type == "U" then
        handle_unsequenced(buffer, subtree, offset, packet_length)
    elseif packet_type == "l" then
        handle_login(buffer, subtree, offset, packet_length)
    elseif packet_type == "r" then
        handle_login_response(buffer, subtree, offset, packet_length)
    elseif packet_type == "c" then
        handle_synchronization_complete(buffer, subtree, offset, packet_length)
    elseif packet_type == "a" then
        handle_retransmission_request(buffer, subtree, offset, packet_length)
    elseif packet_type == "X" then
        handle_logout(buffer, subtree, offset, packet_length)
    elseif packet_type == "G" then
        handle_goodbye(buffer, subtree, offset, packet_length)
    elseif packet_type == "u" then
        handle_session_update(buffer, subtree, offset, packet_length)
    elseif packet_type == "0" then
        handle_server_heartbeat(buffer, subtree, offset, packet_length)
    elseif packet_type == "1" then
        handle_client_heartbeat(buffer, subtree, offset, packet_length)
    elseif packet_type == "T" then
        handle_test(buffer, subtree, offset, packet_length)
    else
        subtree:add_proto_expert_info(e_undecoded, "Unknown packet type: " .. packet_type)
    end
end

-- Register the protocol dissector to a specific port
local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(40010, ESesM)  -- Register the protocol for port 40010
tcp_dissector_table:add_for_decode_as(ESesM)
