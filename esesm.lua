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
ESesM.fields.f_status_code = ProtoField.string("ESesM.status_code", "Status Code", base.ASCII)
ESesM.fields.f_status_code_ok = ProtoField.string("ESesM.status_code", "Status Code OK", base.ASCII)
ESesM.fields.f_synchronization_complete = ProtoField.bytes("ESesM.synchronization_complete", "Synchronization Complete")
ESesM.fields.f_unsequenced_packet = ProtoField.bytes("ESesM.unsequenced_packet", "Unsequenced packet")
ESesM.fields.f_sequenced_packet = ProtoField.bytes("ESesM.sequenced_packet", "sequenced packet")
ESesM.fields.f_new_order = ProtoField.string("ESesM.new_order", "New Order", base.ASCII)
ESesM.fields.f_new_order_response = ProtoField.string("ESesM.new_order_response", "New Order response", base.ASCII)
ESesM.fields.f_reserved = ProtoField.bytes("ESesM.reserved", "Reserved")
ESesM.fields.f_reserved_1 = ProtoField.bytes("ESesM.reserved_1", "Reserved")
ESesM.fields.f_mpid = ProtoField.string("ESesM.mpid", "MPID", base.ASCII)
ESesM.fields.f_client_order_id = ProtoField.string("ESesM.client_oder_id", "Client Orderr ID", base.ASCII)
ESesM.fields.f_symbol_id = ProtoField.bytes("ESesM.symbol_id", "Symbol ID")
ESesM.fields.f_price = ProtoField.bytes("ESesM.price", "Price")
ESesM.fields.f_size = ProtoField.uint32("ESesM.size", "Size", base.DEC)
ESesM.fields.f_order_instructions = ProtoField.string("ESesM.order_instructions", "Order instructions", base.ASCII)
ESesM.fields.f_time_in_force = ProtoField.string("ESesM.time_in_force", "Time in force", base.ASCII)
ESesM.fields.f_order_type = ProtoField.string("ESesM.order_type", "Order type", base.ASCII)
ESesM.fields.f_price_sliding = ProtoField.string("ESesM.price_sliding", "Price slidng", base.ASCII)
ESesM.fields.f_self_trade_protection = ProtoField.string("ESesM.self_trade_protection", "Self trade protection", base.ASCII)
ESesM.fields.f_self_trade_protection_group = ProtoField.string("ESesM.self_trade_protection_group", "Self Trade Protection group", base.ASCII)
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
ESesM.fields.f_matching_engine_time = ProtoField.uint32("ESesM.matching_engine_time", "Matching engine time", base.DEC)
ESesM.fields.f_order_id = ProtoField.uint32("ESesM.order_id", "Order ID", base.DEC)
ESesM.fields.f_modify_order = ProtoField.bytes("ESesM.modify_order", "Modify order")
ESesM.fields.f_modify_order_response = ProtoField.bytes("ESesM.modify_order_response", "Mmodify order response")
ESesM.fields.f_cancel_order = ProtoField.bytes("ESesM.cancel_order", "Cancel order")
ESesM.fields.f_cancel_order_response = ProtoField.bytes("ESesM.cancel_order_response", "Cancel order response")


local e_undecoded = ProtoExpert.new("ESesM.unexpected_packet_type.expert", "Unexpected packet type", expert.group.UNDECODED, expert.severity.ERROR)
local e_packet_too_short = ProtoExpert.new("ESesM.packet_too_short.expert", "Packet is too short", expert.group.MALFORMED, expert.severity.ERROR)
local e_info_message = ProtoField.string("ESesM.info_text", "Info Text")

ESesM.experts = { e_undecoded, e_packet_too_short }

function number_to_binary_str(num, bits)
    bits = bits or 16  -- Default to 16 bits if not specified
    local t = {}
    for b = bits, 1, -1 do
        local rest = math.floor(num / 2^(b - 1))
        num = num % 2^(b - 1)
        t[#t + 1] = (rest % 2 == 1) and "1" or "0"
    end
    return table.concat(t)
end

local new_order_status_descriptions = {
    [" "] = "Successful",
    ["A"] = "Duplicate Client Order ID",
    ["B"] = "Not in Live Order Window",
    ["C"] = "Matching Engine is not available",
    ["D"] = "Duplicate Order Check rejected",
    ["E"] = "Exceeded Test Symbol throttle",
    ["F"] = "ISO orders not allowed",
    ["G"] = "Invalid Self Trade Protection Group or its use",
    ["H"] = "Blocked by MEO user",
    ["I"] = "Invalid MPID",
    ["J"] = "Invalid Price",
    ["K"] = "Invalid Size",
    ["L"] = "Blocked by Firm over MIAX Member Firm Portal or by Helpdesk",
    ["M"] = "Exceeded max allowed size",
    ["N"] = "Exceeded max notional value",
    ["O"] = "Invalid Client Order ID",
    ["P"] = "Request is not permitted for this session",
    ["Q"] = "Short sale orders not allowed",
    ["R"] = "Blocked by Cumulative Risk Metrics",
    ["S"] = "Invalid Symbol ID",
    ["T"] = "Invalid Order Type",
    ["U"] = "Invalid use of Locate Required",
    ["V"] = "Invalid Sell Short",
    ["W"] = "Limit Order Price Protection",
    ["X"] = "MPID not permitted",
    ["Y"] = "ISO attribute not compatible with the order type",
    ["Z"] = "Undefined reason",
    ["a"] = "Invalid Capacity",
    ["b"] = "Invalid Time in Force",
    ["c"] = "Invalid Routing Instruction or its use",
    ["d"] = "Invalid Self Trade Protection Level",
    ["e"] = "Invalid Self Trade Protection Instruction or its use",
    ["f"] = "Invalid Attributable value or use",
    ["g"] = "Invalid Price Sliding and Re-Price Frequency value or use",
    ["h"] = "Invalid use of Post Only instruction",
    ["i"] = "Invalid use of Display instruction",
    ["j"] = "Invalid value or use for Available when Locked Instruction",
    ["k"] = "Market Order Price Protection",
    ["l"] = "Invalid Routing Strategy or its use",
    ["m"] = "Invalid value in Account field",
    ["n"] = "Invalid value in Clearing Account field",
    ["o"] = "Invalid use of Trading Collar Dollar Value",
    ["p"] = "Invalid for current Symbol Trading Status",
    ["q"] = "Primary Exchange IPO Not Complete/IPO in Progress",
    ["r"] = "Invalid use of MinQty size or MinQty Exec Type instruction",
    ["s"] = "Invalid use of Order Type",
    ["t"] = "Invalid MaxFloor Qty",
    ["u"] = "Invalid Display Range Qty",
    ["v"] = "Feature not Available",
    ["w"] = "Primary Listing Market routing not supported",
    ["x"] = "Too late for Primary Listing Market order",
    ["y"] = "PAC Orders are not allowed, routing to Primary Listing Market disabled",
    ["z"] = "Short sale exempt orders not allowed",
    ["0"] = "Limit price more aggressive than Market Impact Collar",
    ["1"] = "Market Orders not allowed",
    ["2"] = "Restricted security not allowed",
    ["3"] = "Blocked by Order Rate Metrics",
    ["4"] = "Average Daily Volume Protection",
    ["5"] = "Invalid offset for Primary Peg Order",
    ["6"] = "Invalid Purge Group specified",
    ["7"] = "Invalid or Not Permitted value in Locate Account field",
    ["8"] = "Blocked by Drop Copy ACOD event",
    ["9"] = "Blocked by Drop Copy ACOSF event",
    ["!"] = "Invalid use of 'Cancel Order if not a NBBO Setter' order instruction",
    ["*"] = "Downgraded from older version"
}

local login_status_descriptions = {
    [" "] = "Successful",
    ["S"] = "Invalid trading session requested for the Matching Engine",
    ["N"] = "Invalid start sequence number requested for the Matching Engine",
    ["U"] = "No active trading session exists for the Matching Engine, Matching Engine unavailable",
    ["X"] = "Rejected: Invalid Username/Computer ID combination",
    ["I"] = "Incompatible Session protocol version",
    ["A"] = "Incompatible Application protocol version",
    ["C"] = "Invalid Number of Matching Engines specified in Login Request",
    ["L"] = "Request rejected because client already logged in"
}

local modify_order_response_status = {
    [" "] = "Successful",
    ["A"] = "Duplicate Client Order ID",
    ["B"] = "Not in Live Order Window",
    ["C"] = "Matching Engine is not available",
    ["D"] = "Cannot find order with Target Client Order ID",
    ["E"] = "Exceeded Test Symbol throttle",
    ["F"] = "Order is routed",
    ["G"] = "Short sale orders not allowed",
    ["H"] = "Blocked by MEO user",
    ["I"] = "Invalid MPID",
    ["J"] = "Invalid Price",
    ["K"] = "Invalid Size",
    ["L"] = "Blocked by Firm over MIAX Member Firm Portal or by Helpdesk",
    ["M"] = "Exceeded max allowed size",
    ["N"] = "Exceeded max notional value",
    ["O"] = "Invalid Client Order ID",
    ["P"] = "Request is not permitted for this session",
    ["Q"] = "Specified MPID does not match target order",
    ["R"] = "Blocked by Cumulative Risk Metrics",
    ["S"] = "Invalid Symbol ID",
    ["T"] = "Invalid Target Client Order Id",
    ["U"] = "Invalid use of Locate Required",
    ["V"] = "Invalid Sell Short",
    ["W"] = "Limit Order Price Protection",
    ["X"] = "MPID not permitted",
    ["Z"] = "Undefined reason",
    ["a"] = "Invalid MinQty modification",
    ["b"] = "Invalid to change MaxFloor Qty",
    ["c"] = "Modification request is sent to another market and pending completion",
    ["d"] = "Not allowed, Order is already pending modification",
    ["t"] = "Invalid MaxFloor Qty",
    ["y"] = "PAC Orders are not allowed, routing to Primary Listing Market disabled",
    ["z"] = "Short sale exempt orders not allowed",
    ["0"] = "Limit price more aggressive than Market Impact Collar",
    ["1"] = "Market Orders not allowed",
    ["2"] = "Restricted security not allowed",
    ["3"] = "Blocked by Order Rate Metrics",
    ["4"] = "Average Daily Volume Protection",
    ["7"] = "Invalid or Not Permitted value in Locate Account field",
    ["8"] = "Blocked by Drop Copy ACOD event",
    ["9"] = "Blocked by Drop Copy ACOSF event",
    ["*"] = "Downgraded from older version"
}

local cancel_order_response_status = {
    [" "] = "Successful",
    ["A"] = "Duplicate Client Order ID",
    ["B"] = "Not in Live Order Window",
    ["C"] = "Matching Engine is not available",
    ["D"] = "Cannot find order with Target Client Order ID",
    ["E"] = "Exceeded Test Symbol throttle",
    ["F"] = "Routed order already pending cancel",
    ["I"] = "Invalid MPID",
    ["O"] = "Invalid Client Order ID",
    ["P"] = "Request is not permitted for this session",
    ["Q"] = "Specified MPID does not match target order",
    ["S"] = "Invalid Symbol ID",
    ["T"] = "Invalid Target Order ID",
    ["X"] = "MPID not permitted",
    ["Z"] = "Undefined reason",
    ["c"] = "Cancellation Request is routed to another market and pending completion",
    ["*"] = "Downgraded from older version"
}

local cancel_by_exchange_order_id_status = {
    [" "] = "Successful",
    ["A"] = "Duplicate Client Order ID",
    ["B"] = "Not in Live Order Window",
    ["C"] = "Matching Engine is not available",
    ["D"] = "Cannot find order with specified Order ID",
    ["E"] = "Exceeded Test Symbol throttle",
    ["F"] = "Routed order already pending cancel",
    ["G"] = "Cannot cancel order submitted by a FIX session",
    ["H"] = "Invalid Order ID",
    ["I"] = "Invalid MPID",
    ["O"] = "Invalid Client Order ID",
    ["P"] = "Request is not permitted for this session",
    ["Q"] = "Specified MPID does not match target order",
    ["S"] = "Invalid Symbol ID",
    ["X"] = "MPID not permitted",
    ["Z"] = "Undefined reason",
    ["c"] = "Cancellation Request is routed to another market and pending completion",
    ["*"] = "Downgraded from older version"
}

local mass_cancel_response_status = {
    [" "] = "Successful",
    ["I"] = "Invalid MPID",
    ["X"] = "MPID not permitted",
    ["P"] = "Request is not permitted for this session",
    ["R"] = "Invalid Scope",
    ["A"] = "Invalid action",
    ["C"] = "Matching Engine not available",
    ["U"] = "State of the request for this Matching Engine is unknown",
    ["O"] = "Invalid Client Order ID",
    ["Z"] = "Undefined reason",
    ["6"] = "Invalid Purge Group specified",
    ["*"] = "Downgraded from older version"
}

local cancel_reduce_size_order_reason = {
    ["A"] = "Cancelled due to Cumulative Risk Metrics",
    ["B"] = "Reserved for future use",
    ["C"] = "Time in Force cancelled",
    ["D"] = "Auto Cancel on Disconnect (ACOD)",
    ["E"] = "Post Only order is locking/crossing MIAX Pearl Equities BBO",
    ["F"] = "Auto Cancel on System Failure (ACOSF)",
    ["G"] = "Cancelled due to price sliding instruction",
    ["H"] = "Cancelled by Helpdesk or over MIAX Member Firm Portal",
    ["I"] = "Order Expired",
    ["J"] = "Symbol trading status makes PAC Market order non tradeable",
    ["K"] = "Trading Collar Protection",
    ["L"] = "Sell Short ISO when Short Sale Price Test is in effect",
    ["M"] = "Symbol is not trading",
    ["N"] = "Limit Order Price Protection",
    ["O"] = "Route to Primary Listing Market Rejected",
    ["P"] = "Cancelled by a Mass Cancel Request over a Priority Purge port",
    ["Q"] = "Unexpected Cancel by Primary Listing Market",
    ["R"] = "Cancelled due to failed Price Improvement route",
    ["S"] = "Cancelled due to Primary Auction route timeout",
    ["T"] = "Cancelled due to Order Rate Protection",
    ["U"] = "Cancelled by user through order entry session",
    ["V"] = "Invalid Pegged Order Price",
    ["W"] = "PAC Order Cancelled as Security is halted and Closing Auction at Primary Listing Market will not be conducted.",
    ["X"] = "Not Applicable. Used when Pending Cancel Status is 'X'",
    ["Y"] = "Primary Auction order is Cancelled due to a modification reject from Primary Listing Market.",
    ["0"] = "Cancelled due to Market Impact Collar",
    ["1"] = "Full cancel due to Self-Trade Protection - Cancel Newest Instruction",
    ["2"] = "Full cancel due to Self-Trade Protection - Cancel Oldest Instruction",
    ["3"] = "Full cancel due to Self-Trade Protection - Cancel Both Instruction",
    ["4"] = "Full/Partial cancel due to Self-Trade Protection - Decrement and Cancel Instruction",
    ["5"] = "Cancelled due to Drop Copy ACOD event",
    ["6"] = "Cancelled due to Drop Copy ACOSF event",
    ["7"] = "Cancelled as order did not set NBBO",
    ["8"] = "Cancelled by user through a session other than the order entry session",
    ["Z"] = "Undefined reason",
    ["*"] = "Downgraded from older version"
}

local executing_trading_center = {
    ['A'] = "NYSE American",
    ['B'] = "NASDAQ BX",
    ['C'] = "NYSE National",
    ['H'] = "MIAX Pearl Equities",
    ['I'] = "NASDAQ ISE",
    ['J'] = "CBOE EDGA Exchange",
    ['K'] = "CBOE EDGX Exchange",
    ['L'] = "Long-Term Stock Exchange",
    ['M'] = "NYSE Chicago",
    ['N'] = "New York Stock Exchange",
    ['P'] = "NYSE Arca",
    ['Q'] = "NASDAQ",
    ['U'] = "Members Exchange",
    ['V'] = "Investors’ Exchange",
    ['X'] = "NASDAQ PHLX",
    ['Y'] = "CBOE BYX Exchange",
    ['Z'] = "CBOE BZX Exchange"
}


function get_status_description(code, status_dict)
    return status_dict[code] or "Unknown status code"
end

function get_trading_center(code)
    return executing_trading_center[code] or "Unknown trading center"
end

local function process_status_login(buffer, subtree, offset)
    local status = buffer(offset, 1):string()

    if status == " " then
        subtree:add(ESesM.fields.f_status_code_ok, buffer(offset, 1))
    else
        local item = subtree:add(ESesM.fields.f_status_code, buffer(offset, 1))
        item:add_proto_expert_info(e_undecoded, get_status_description(status, login_status_descriptions))
    end
end

local function process_status_new_order(buffer, subtree, offset)
    local status = buffer(offset, 1):string()

    if status == " " then
        subtree:add(ESesM.fields.f_status_code_ok, buffer(offset, 1))
    else
        local item = subtree:add(ESesM.fields.f_status_code, buffer(offset, 1))
        item:add_proto_expert_info(e_undecoded, get_status_description(status, new_order_status_descriptions))
    end
end

local function process_cancel_order_response(buffer, subtree, offset, packet_length)
end

local function process_modify_order_response(buffer, subtree, offset, packet_length)
end

local function process_modify_order(buffer, subtree, offset, packet_length)
end

local function process_cancel_order(buffer, subtree, offset, packet_length)
end
    

-- Function to process New Order Response (NR)
local function process_new_order_response(buffer, subtree, offset, packet_length)
    subtree:add(ESesM.fields.f_matching_engine_time, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_mpid, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_client_order_id, buffer(offset, 20))
    offset = offset + 20
    subtree:add_le(ESesM.fields.f_symbol_id, buffer(offset, 4))
    offset = offset + 4
    subtree:add_le(ESesM.fields.f_order_id, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_price, buffer(offset, 8))
    offset = offset + 8
    subtree:add_le(ESesM.fields.f_size, buffer(offset, 4))
    offset = offset + 4
    process_status_new_order(buffer, subtree, offset)
    offset = offset + 1
    subtree:add(ESesM.fields.f_reserved, buffer(offset, 10))
    offset = offset + 10
end

-- Function to process New Order (N1)
local function process_new_order(buffer, subtree, offset, packet_length)
    subtree:add(ESesM.fields.f_reserved, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_mpid, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_client_order_id, buffer(offset, 20))
    offset = offset + 20
    subtree:add_le(ESesM.fields.f_symbol_id, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_price, buffer(offset, 8))
    offset = offset + 8
    subtree:add_le(ESesM.fields.f_size, buffer(offset, 4))
    offset = offset + 4

    local order_instructions_field = buffer(offset, 2)  -- Read 2 bytes (16 bits)
    local order_instructions_value = order_instructions_field:le_uint()  -- Read 2 bytes (16 bits)
    local order_instructions_binary_str = number_to_binary_str(order_instructions_value, 16)    
    subtree:add(ESesM.fields.f_order_instructions, order_instructions_field, order_instructions_binary_str)
    offset = offset + 2

    subtree:add(ESesM.fields.f_time_in_force, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_order_type, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_price_sliding, buffer(offset, 1))
    offset = offset + 1

    local self_trade_protection_field = buffer(offset, 1)
    local self_trade_protection_value = self_trade_protection_field:le_uint()  -- Read 2 bytes (16 bits)
    local self_trade_protection_binary_str = number_to_binary_str(order_instructions_value, 16)    
    subtree:add(ESesM.fields.f_self_trade_protection, self_trade_protection_field, self_trade_protection_binary_str)
    offset = offset + 1

    subtree:add(ESesM.fields.f_self_trade_protection_group, buffer(offset, 1))
    offset = offset + 1
    subtree:add_le(ESesM.fields.f_routing, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_collar_dollar_value, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_capacity, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_account, buffer(offset, 16))
    offset = offset + 16
    subtree:add(ESesM.fields.f_clearing_account, buffer(offset, 4))
    offset = offset + 4
    subtree:add_le(ESesM.fields.f_min_qty, buffer(offset, 4))
    offset = offset + 4
    subtree:add_le(ESesM.fields.f_max_floor_qty, buffer(offset, 4))
    offset = offset + 4
    subtree:add_le(ESesM.fields.f_display_range_qty, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_peg_offset, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.f_locate_account, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.f_purge_group,buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.f_reserved_1, buffer(offset, 19))
    offset = offset + 19
end

local function handle_sequenced(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.f_sequenced_packet, data)
    offset = offset + 1
end

local function handle_unsequenced(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.f_unsequenced_packet, data)
    offset = offset + 1

    local packet_type = buffer(offset, 2):string()
    if packet_type == "N1" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.f_new_order, buffer(offset, packet_length-offset))
        process_new_order(buffer, item, offset, packet_length)
    elseif packet_type == "NR" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.f_new_order_response, buffer(offset, packet_length-offset))
        process_new_order_response(buffer, item, offset, packet_length)
    elseif packet_type == "M1" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.f_modify_order, buffer(offset, packet_length-offset))
        process_modify_order(buffer, item, offset, packet_length)
    elseif packet_type == "MR" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.f_modify_order_response, buffer(offset, packet_length-offset))
        process_modify_order_response(buffer, item, offset, packet_length)
    elseif packet_type == "CO" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.f_cancel_order, buffer(offset, packet_length-offset))
        process_cancel_order(buffer, item, offset, packet_length)
    elseif packet_type == "CR" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.f_cancel_order_response, buffer(offset, packet_length-offset))
        process_cancel_order_response(buffer, item, offset, packet_length)
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

    process_status_login(buffer, subtree, offset)
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
