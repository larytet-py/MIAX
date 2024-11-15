-- Define the protocol fields
local ESesM = Proto("ESesM", "MIAX ESesM")
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
ESesM.fields.f_synchronization_complete = ProtoField.bytes("ESesM.synchronization_complete", "Synchronization Complete")
ESesM.fields.f_unsequenced_packet = ProtoField.bytes("ESesM.unsequenced_packet", "Unsequenced packet")
ESesM.fields.f_sequenced_packet = ProtoField.bytes("ESesM.sequenced_packet", "sequenced packet")
ESesM.fields.f_new_order = ProtoField.string("ESesM.new_order", "New Order", base.ASCII)
ESesM.fields.f_new_order_response = ProtoField.string("ESesM.new_order_response", "New Order response", base.ASCII)
ESesM.fields.f_reserved = ProtoField.bytes("ESesM.reserved", "Reserved")
ESesM.fields.f_mpid = ProtoField.string("ESesM.mpid", "MPID", base.ASCII)
ESesM.fields.f_client_order_id = ProtoField.string("ESesM.client_oder_id", "Client Orderr ID", base.ASCII)
ESesM.fields.f_symbol_id = ProtoField.bytes("ESesM.symbol_id", "Symbol ID")
ESesM.fields.f_price = ProtoField.bytes("ESesM.price", "Price")
ESesM.fields.f_size = ProtoField.uint32("ESesM.size", "Size", base.DEC)
ESesM.fields.f_order_instructions = ProtoField.uint16("ESesM.size", "Size", base.DEC)
ESesM.fields.f_time_in_force = ProtoField.string("ESesM.time_in_force", "Time in force", base.ASCII)
ESesM.fields.f_order_type = ProtoField.string("ESesM.order_type", "Order type", base.ASCII)
ESesM.fields.f_price_sliding = ProtoField.string("ESesM.price_sliding", "Price slidng", base.ASCII)
ESesM.fields.f_self_trade_protection = ProtoField.uint8("ESesM.self_trade_protection", "Trade protection", base.DEC)
ESesM.fields.f_self_trade_protection_group = ProtoField.string("ESesM.self_trade_protection_group", "Self Trade Protection Ggroup", base.ASCII)
ESesM.fields.f_routing = ProtoField.uint8("ESesM.routing", "Routing", base.DEC)
ESesM.fields.f_collar_dollar_value = ProtoField.bytes("ESesM.collar_dollar_value", "Collar dollar value")
ESesM.fields.f_capacity = ProtoField.string("ESesM.capacity", "Capacity", base.ASCII)
ESesM.fields.f_account = ProtoField.string("ESesM.account", "Account", base.ASCII)
ESesM.fields.f_clearing_account = ProtoField.string("ESesM.clearing_account", "Clearing Account", base.ASCII)
ESesM.fields.f_min_qty = ProtoField.uint32("ESesM.min_qty", "Min QTY", base.DEC)
ESesM.fields.f_max_floor_qty = ProtoField.uint32("ESesM.min_floor_qty", "Min floor QTY", base.DEC)
ESesM.fields.f_display_range_qty = ProtoField.uint32("ESesM.display_range_qty", "Display ange QTY", base.DEC)
ESesM.fields.f_peg_offset = ProtoField.bytes("ESesM.peg_offset", "Peg offset")
ESesM.fields.f_locate_account = ProtoField.string("ESesM.locate_account", "Locate Account", base.ASCII)
ESesM.fields.f_purge_group = ProtoField.string("ESesM.purge_group", "Purge group", base.ASCII)


local e_undecoded = ProtoExpert.new("ESesM.unexpected_packet_type.expert", "Unexpected packet type", expert.group.UNDECODED, expert.severity.ERROR)
local e_packet_too_short = ProtoExpert.new("ESesM.packet_too_short.expert", "Packet is too short", expert.group.MALFORMED, expert.severity.ERROR)
local e_info_message = ProtoField.string("ESesM.info_text", "Info Text")

ESesM.experts = { e_undecoded, e_packet_too_short }

-- Function to process New Order (N1)
local function process_new_order(buffer, subtree, offset, packet_length)
    subtree:add(ESesM.fields.f_reserved, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_mpid, buffer(offset, 4))
    offset = offset + 8
    subtree:add(ESesM.fields.f_client_order_id, buffer(offset, 20))
    offset = offset + 20
    subtree:add(ESesM.fields.f_symbol_id, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_price, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_size, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_order_instructions, buffer(offset, 2))
    offset = offset + 2
    subtree:add(ESesM.fields.f_time_in_force, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_order_type, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_price_sliding, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_self_trade_protection, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_self_trade_protection_group, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_routing, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_collar_dollar_value, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_capacity, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_account buffer(offset, 16))
    offset = offset + 16
    subtree:add(ESesM.fields.f_clearing_account buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_min_qty buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_max_floor_qty buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_display_range_qty buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_peg_offset buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_locate_account buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_purge_group buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.reserved buffer(offset, 19))
    offset = offset + 19
end

-- Function to process New Order Response (NR)
local function process_new_order_response(buffer, subtree, offset, packet_length)
end

-- Function to handle Sequenced packets
local function handle_sequenced(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.f_sequenced_packet, data)
    offset = offset + 1
end

-- Function to handle Unsequenced packets
local function handle_unsequenced(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.f_unsequenced_packet, data)
    offset = offset + 1

    local packet_type = buffer(offset, 2):string()
    if packet_type == "N1" then
        offset = offset + 2
        subtree:add(ESesM.fields.f_new_order, buffer(offset, packet_length-offset))
        process_new_order(buffer, subtree, offset, packet_length)
    elseif packet_type == "NR" then
        offset = offset + 2
        subtree:add(ESesM.fields.f_new_order_response, buffer(offset, packet_length-offset))
        process_new_order_response(buffer, subtree, offset, packet_length)
    else
        local item = subtree:add(ESesM.fields.f_new_order, buffer(offset, packet_length-offset))
        item:add_proto_expert_info(e_undecoded, "Unexpected unsequenced packet type: " .. packet_type)
    end
end

LoginManager = {
    number_of_matching_engines = nil
}

local function handle_login(buffer, subtree, offset, packet_length)  
    local data = buffer(offset, packet_length-offset)
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

    LoginManager.number_of_matching_engines = buffer(offset, 1):le_uint()
    subtree:add_le(ESesM.fields.f_number_of_matching_engines, buffer(offset, 1))    
    offset = offset + 1
end

local function handle_login_response(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.f_login_response, data)
    offset = offset + 1

    local number_of_matching_engines = buffer(offset, 1):le_uint()    
    local item = subtree:add_le(ESesM.fields.f_number_of_matching_engines, buffer(offset, 1))    
    if number_of_matching_engines ~= LoginManager.number_of_matching_engines then 
        item:add_proto_expert_info(e_undecoded, "Mismatch number of number of matching engines")
    end
    offset = offset + 1

    local status = buffer(offset,1):string()
    if status == " " then
        subtree:add(ESesM.fields.f_status_code_ok, buffer(offset, 1))
    else
        local item = subtree:add(ESesM.fields.f_status_code, buffer(offset, 1))
        item:add_proto_expert_info(e_undecoded, "Not Ok")
    end
    offset = offset + 1
end

local function handle_synchronization_complete(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.f_synchronization_complete, data)
    offset = offset + 1
    subtree:add_le(ESesM.fields.f_number_of_matching_engines, buffer(offset, 1))    
    offset = offset + 1
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
    if length < 1 then
        subtree:add_proto_expert_info(e_packet_too_short, "Packet is too short")
        return
    end
    if  buffer:len() < length then
        subtree:add_proto_expert_info(e_packet_too_short, "The TCP payload size doesn't fit the packet length")
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
