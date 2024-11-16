local bitop = require("bit32")
local baseName = "ESesM"
local ESesM = Proto(baseName, "MIAX " .. baseName)


local fields = {
    packet_length                     = {"uint16", "Length",                        base.DEC},
    login                             = {"bytes",  "Login"},
    login_response                    = {"bytes",  "Login Response"},
    version                           = {"string", "Version"},
    username                          = {"string", "Username"},
    computer_id                       = {"string", "Computer ID"},
    application_protocol              = {"string", "Application protocol"},
    number_of_matching_engines        = {"uint16", "Matching Engines",             base.DEC},
    status_code                       = {"string", "Status Code",                  base.ASCII},
    status_code_ok                    = {"string", "Status Code OK",               base.ASCII},
    synchronization_complete          = {"bytes",  "Synchronization Complete"},
    unsequenced_packet                = {"bytes",  "Unsequenced packet"},
    sequenced_packet                  = {"bytes",  "Sequenced packet"},
    new_order                         = {"string", "New Order",                    base.ASCII},
    new_order_response                = {"string", "New Order response",           base.ASCII},
    reserved                          = {"bytes",  "Reserved"},
    reserved_1                        = {"bytes",  "Reserved"},
    mpid                              = {"string", "MPID",                         base.ASCII},
    client_order_id                   = {"string", "Client Order ID",              base.ASCII},
    symbol_id                         = {"bytes",  "Symbol ID"},
    price                             = {"bytes",  "Price"},
    size                              = {"uint32", "Size",                         base.DEC},
    order_instructions                = {"string", "Order instructions",           base.ASCII},
    time_in_force                     = {"string", "Time in force",                base.ASCII},
    order_type                        = {"string", "Order type",                   base.ASCII},
    price_sliding                     = {"string", "Price sliding",                base.ASCII},
    self_trade_protection             = {"string", "Self trade protection",        base.ASCII},
    self_trade_protection_group       = {"string", "Self Trade Protection group",  base.ASCII},
    routing                           = {"uint8",  "Routing",                      base.DEC},
    collar_dollar_value               = {"bytes",  "Collar dollar value"},
    capacity                          = {"string", "Capacity",                     base.ASCII},
    account                           = {"string", "Account",                      base.ASCII},
    clearing_account                  = {"string", "Clearing Account",             base.ASCII},
    min_qty                           = {"uint32", "Min QTY",                      base.DEC},
    max_floor_qty                     = {"uint32", "Min floor QTY",                base.DEC},
    display_range_qty                 = {"uint32", "Display range QTY",            base.DEC},
    peg_offset                        = {"bytes",  "Peg offset"},
    locate_account                    = {"string", "Locate Account",               base.ASCII},
    purge_group                       = {"string", "Purge group",                  base.ASCII},
    matching_engine_time              = {"uint64", "Matching engine time",         base.DEC},
    order_id                          = {"uint32", "Order ID",                     base.DEC},
    modify_order                      = {"bytes",  "Modify order"},
    modify_order_response             = {"bytes",  "Modify order response"},
    cancel_order                      = {"bytes",  "Cancel order"},
    cancel_order_response             = {"bytes",  "Cancel order response"},
    system_state_notification         = {"bytes",  "System state notification"},
    new_order_notification            = {"bytes",  "New order notification"},
    modify_order_notification         = {"bytes",  "Modify order notification"},
    cancel_order_notification         = {"bytes",  "Cancel order notification"},
    price_update_notification         = {"bytes",  "Price update notification"},
    reserve_replenishment_notification= {"bytes",  "Reserve replenishment notification"},
    symbol_update                     = {"bytes",  "Symbol update"},
    execution_notification            = {"bytes",  "Execution notification"},
    sequence_number                   = {"uint64", "Sequence number",              base.DEC},
    matching_engine_id                = {"uint8",  "Matching engine ID",           base.DEC},
    meo_version                       = {"string", "MEO version",                  base.ASCII},
    session_id                        = {"uint8",  "Session ID",                   base.DEC},
    system_status                     = {"string", "System status",                base.ASCII},
    ticker_symbol                     = {"string", "Ticker symbol",                base.ASCII},


    order_side                        = {"string", "Side",                         base.NONE},
    order_short_sale_indicator        = {"uint8",  "Short Sale Indicator",         base.DEC},  
    order_displayed                   = {"bool",   "Displayed"},  
    order_postonly                    = {"bool",   "PostOnly"},  
    order_locate_required             = {"bool",   "Locate Required"},  
    order_iso                         = {"bool",   "ISO"},  
    order_retail_order                = {"bool",   "Retail Order"},  
    order_attributable_order          = {"uint8",  "Attributable Order",           base.DEC},  
    order_minqty_exec_type            = {"uint8",  "MinQty Exec Type",             base.DEC},  
    order_nbbo_setter_cancel          = {"bool",   "Cancel Order if NOT a NBBO Setter"},  
    order_reserved                    = {"uint8",  "Reserved",                     base.HEX}
}

local function createFieldId(baseName, fieldName)
    return baseName .. "." .. fieldName:gsub("_", ".")
end

-- Declare all possible protocol fields as required by Wireshark.
-- Initialize all ProtoFields with the dynamically constructed IDs and properties
-- This is an equivalent of a lof lines like 
--    ESesM.fields.packet_length = ProtoField.uint16("ESesM.packet_length", "Length", base.DEC)
for key, val in pairs(fields) do
    local dtype, desc, base = unpack(val)
    local fieldId = string.format("%s.%s", baseName, key:gsub("_", "."))
    if base then
        ESesM.fields[key] = ProtoField[dtype](fieldId, desc, base)
    else
        ESesM.fields[key] = ProtoField[dtype](fieldId, desc)
    end
end


local e_undecoded = ProtoExpert.new("ESesM.unexpected_packet_type.expert", "Unexpected packet type", expert.group.UNDECODED, expert.severity.ERROR)
local e_packet_too_short = ProtoExpert.new("ESesM.packet_too_short.expert", "Packet is too short", expert.group.MALFORMED, expert.severity.ERROR)
local e_info_message = ProtoField.string("ESesM.info_text", "Info Text")

ESesM.experts = { e_undecoded, e_packet_too_short }

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

local function process_status_login(buffer, subtree, offset)
    local status = buffer(offset, 1):string()

    if status == " " then
        subtree:add(ESesM.fields.status_code_ok, buffer(offset, 1))
    else
        local item = subtree:add(ESesM.fields.status_code, buffer(offset, 1))
        item:add_proto_expert_info(e_undecoded, get_status_description(status, login_status_descriptions))
    end
end

local function process_status_new_order(buffer, subtree, offset)
    local status = buffer(offset, 1):string()

    if status == " " then
        subtree:add(ESesM.fields.status_code_ok, buffer(offset, 1))
    else
        local item = subtree:add(ESesM.fields.status_code, buffer(offset, 1))
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
    
local function process_execution_notification(buffer, subtree, offset, packet_length)
end

local function process_modify_order_notification(buffer, subtree, offset, packet_length)
end

local function process_system_state_notification(buffer, subtree, offset, packet_length)
    subtree:add_le(ESesM.fields.matching_engine_time, buffer(offset, 8))
    offset = offset + 8  
    subtree:add(ESesM.fields.meo_version, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.session_id, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.system_status, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.reserved, buffer(offset, 8))
    offset = offset + 8
end

local function process_new_order_notification(buffer, subtree, offset, packet_length)
end

local function process_cancel_order_notification(buffer, subtree, offset, packet_length)
end

local function process_price_update_notification(buffer, subtree, offset, packet_length)
end

local function process_reserve_replenishment_notification(buffer, subtree, offset, packet_length)
end

local function process_symbol_update(buffer, subtree, offset, packet_length)
    subtree:add_le(ESesM.fields.matching_engine_time, buffer(offset, 8))
    offset = offset + 8  
    subtree:add(ESesM.fields.symbol_id, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.ticker_symbol, buffer(offset, 11))
    offset = offset + 11
end


-- Function to process New Order Response (NR)
local function process_new_order_response(buffer, subtree, offset, packet_length)
    subtree:add_le(ESesM.fields.matching_engine_time, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.mpid, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.client_order_id, buffer(offset, 20))
    offset = offset + 20
    subtree:add_le(ESesM.fields.symbol_id, buffer(offset, 4))
    offset = offset + 4
    subtree:add_le(ESesM.fields.order_id, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.price, buffer(offset, 8))
    offset = offset + 8
    subtree:add_le(ESesM.fields.size, buffer(offset, 4))
    offset = offset + 4
    process_status_new_order(buffer, subtree, offset)
    offset = offset + 1
    subtree:add(ESesM.fields.reserved, buffer(offset, 10))
    offset = offset + 10
end


local function decode_order_instructions(value)
    local t = {}

    -- Side
    t.side = bit32.band(bit32.rshift(value, 0), 0x01)
    t.side_desc = (t.side == 0) and "Buy" or "Sell"

    -- Short Sale Indicator
    t.short_sale_indicator = bit32.band(bit32.rshift(value, 1), 0x03)
    if t.short_sale_indicator == 0 then
        t.short_sale_indicator_desc = "Not Applicable (when buying)"
    elseif t.short_sale_indicator == 1 then
        t.short_sale_indicator_desc = "Sell Long"
    elseif t.short_sale_indicator == 2 then
        t.short_sale_indicator_desc = "Sell Short"
    end

    -- Displayed
    t.displayed = bit32.band(bit32.rshift(value, 3), 0x01)
    t.displayed_desc = (t.displayed == 0) and "No" or "Yes"

    -- PostOnly
    t.postonly = bit32.band(bit32.rshift(value, 4), 0x01)
    t.postonly_desc = (t.postonly == 0) and "No" or "Yes"

    -- Locate Required
    t.locate_required = bit32.band(bit32.rshift(value, 5), 0x01)
    t.locate_required_desc = (t.locate_required == 0) and "No/Not Applicable" or "Yes"

    -- ISO
    t.iso = bit32.band(bit32.rshift(value, 6), 0x01)
    t.iso_desc = (t.iso == 0) and "No" or "Yes"

    -- Retail Order
    t.retail_order = bit32.band(bit32.rshift(value, 7), 0x01)
    t.retail_order_desc = (t.retail_order == 0) and "No" or "Yes"

    -- Attributable Order
    t.attributable_order = bit32.band(bit32.rshift(value, 8), 0x03)
    if t.attributable_order == 0 then
        t.attributable_order_desc = "No"
    elseif t.attributable_order == 1 then
        t.attributable_order_desc = "Attributed to Firm MPID"
    elseif t.attributable_order == 2 then
        t.attributable_order_desc = "Attributed 'RTAL' to this order"
    end

    -- MinQty Exec Type
    t.minqty_exec_type = bit32.band(bit32.rshift(value, 10), 0x03)
    if t.minqty_exec_type == 0 then
        t.minqty_exec_type_desc = "Not Applicable"
    elseif t.minqty_exec_type == 1 then
        t.minqty_exec_type_desc = "Only single contra order can fulfill MinQty requirement"
    elseif t.minqty_exec_type == 2 then
        t.minqty_exec_type_desc = "Multiple contra orders can fulfill MinQty requirement"
    end

    -- Cancel Order if NOT a NBBO Setter
    t.nbbo_setter_cancel = bit32.band(bit32.rshift(value, 12), 0x01)
    t.nbbo_setter_cancel_desc = (t.nbbo_setter_cancel == 0) and "No" or "Yes"

    -- Reserved bits
    t.reserved = bit32.band(bit32.rshift(value, 13), 0x07)  -- Last 3 bits (13-15)

    return t
end

local function add_order_instructions_to_subtree(subtree, value)
    local decoded = decode_order_instructions(value)
    subtree:add(ESesM.fields.order_side, decoded.side, string.format("Side: %s", decoded.side_desc))
    subtree:add(ESesM.fields.order_short_sale_indicator, decoded.short_sale_indicator, string.format("Short Sale Indicator: %s", decoded.short_sale_indicator_desc))
    subtree:add(ESesM.fields.order_displayed, decoded.displayed, string.format("Displayed: %s", decoded.displayed_desc))
    subtree:add(ESesM.fields.order_postonly, decoded.postonly, string.format("PostOnly: %s", decoded.postonly_desc))
    subtree:add(ESesM.fields.order_locate_required, decoded.locate_required, string.format("Locate Required: %s", decoded.locate_required_desc))
    subtree:add(ESesM.fields.order_iso, decoded.iso, string.format("ISO: %s", decoded.iso_desc))
    subtree:add(ESesM.fields.order_retail_order, decoded.retail_order, string.format("Retail Order: %s", decoded.retail_order_desc))
    subtree:add(ESesM.fields.order_attributable_order, decoded.attributable_order, string.format("Attributable Order: %s", decoded.attributable_order_desc))
    subtree:add(ESesM.fields.order_minqty_exec_type, decoded.minqty_exec_type, string.format("MinQty Exec Type: %s", decoded.minqty_exec_type_desc))
    subtree:add(ESesM.fields.order_nbbo_setter_cancel, decoded.nbbo_setter_cancel, string.format("Cancel Order if NOT a NBBO Setter: %s", decoded.nbbo_setter_cancel_desc))
    subtree:add(ESesM.fields.order_reserved, decoded.reserved, number_to_binary_str(decoded.reserved))
end

-- Function to process New Order (N1)
local function process_new_order(buffer, subtree, offset, packet_length)
    subtree:add(ESesM.fields.reserved, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.mpid, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.client_order_id, buffer(offset, 20))
    offset = offset + 20
    subtree:add_le(ESesM.fields.symbol_id, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.price, buffer(offset, 8))
    offset = offset + 8
    subtree:add_le(ESesM.fields.size, buffer(offset, 4))
    offset = offset + 4


    local order_instructions_field = buffer(offset, 2)  -- Read 2 bytes (16 bits)
    local order_instructions_value = order_instructions_field:le_uint()  -- Read 2 bytes (16 bits)
    order_instructions_subtree = subtree:add(ESesM.fields.order_instructions, order_instructions_field, number_to_binary_str(order_instructions_value))
    add_order_instructions_to_subtree(order_instructions_subtree, order_instructions_value)
    offset = offset + 2

    subtree:add(ESesM.fields.time_in_force, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.order_type, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.price_sliding, buffer(offset, 1))
    offset = offset + 1

    local self_trade_protection_field = buffer(offset, 1)
    local self_trade_protection_value = self_trade_protection_field:le_uint()  -- Read 2 bytes (16 bits)
    local self_trade_protection_binary_str = number_to_binary_str(self_trade_protection_value, 16)    
    subtree:add(ESesM.fields.self_trade_protection, self_trade_protection_field, self_trade_protection_binary_str)
    offset = offset + 1

    subtree:add(ESesM.fields.self_trade_protection_group, buffer(offset, 1))
    offset = offset + 1
    subtree:add_le(ESesM.fields.routing, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.collar_dollar_value, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.capacity, buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.account, buffer(offset, 16))
    offset = offset + 16
    subtree:add(ESesM.fields.clearing_account, buffer(offset, 4))
    offset = offset + 4
    subtree:add_le(ESesM.fields.min_qty, buffer(offset, 4))
    offset = offset + 4
    subtree:add_le(ESesM.fields.max_floor_qty, buffer(offset, 4))
    offset = offset + 4
    subtree:add_le(ESesM.fields.display_range_qty, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.peg_offset, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.locate_account, buffer(offset, 4))
    offset = offset + 4
    subtree:add(ESesM.fields.purge_group,buffer(offset, 1))
    offset = offset + 1
    subtree:add(ESesM.fields.reserved_1, buffer(offset, 19))
    offset = offset + 19
end

local function handle_sequenced(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    local sequenced_packet_tree = subtree:add(ESesM.fields.sequenced_packet, data)
    offset = offset + 1

    sequenced_packet_tree:add_le(ESesM.fields.sequence_number, buffer(offset, 8))
    offset = offset + 8
    sequenced_packet_tree:add_le(ESesM.fields.matching_engine_id, buffer(offset, 1))
    offset = offset + 1

    local packet_type = buffer(offset, 2):string()
    if packet_type == "SU" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.symbol_update, buffer(offset, packet_length-offset))
        process_symbol_update(buffer, item, offset, packet_length)
    elseif packet_type == "NR" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.new_order_response, buffer(offset, packet_length-offset))
        process_new_order_response(buffer, item, offset, packet_length)
    elseif packet_type == "MR" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.modify_order_response, buffer(offset, packet_length-offset))
        process_modify_order_response(buffer, item, offset, packet_length)
    elseif packet_type == "CR" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.cancel_order_response, buffer(offset, packet_length-offset))
        process_cancel_order_response(buffer, item, offset, packet_length)
    elseif packet_type == "SN" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.system_state_notification, buffer(offset, packet_length-offset))
        process_system_state_notification(buffer, item, offset, packet_length)
    elseif packet_type == "O1" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.new_order_notification, buffer(offset, packet_length-offset))
        process_new_order_notification(buffer, item, offset, packet_length)
    elseif packet_type == "MN" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.modify_order_notification, buffer(offset, packet_length-offset))
        process_modify_order_notification(buffer, item, offset, packet_length)
    elseif packet_type == "XN" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.cancel_order_notification, buffer(offset, packet_length-offset))
        process_cancel_order_notification(buffer, item, offset, packet_length)
    elseif packet_type == "PU" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.price_update_notification, buffer(offset, packet_length-offset))
        process_price_update_notification(buffer, item, offset, packet_length)
    elseif packet_type == "RA" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.reserve_replenishment_notification, buffer(offset, packet_length-offset))
        process_reserve_replenishment_notification(buffer, item, offset, packet_length)
    elseif packet_type == "E1" then
        offset = offset + 2
        local item = sequenced_packet_tree:add(ESesM.fields.execution_notification, buffer(offset, packet_length-offset))
        process_execution_notification(buffer, item, offset, packet_length)
    else
        local item = sequenced_packet_tree:add(ESesM.fields.new_order, buffer(offset, packet_length-offset))
        item:add_proto_expert_info(e_undecoded, "Unexpected unsequenced packet type: " .. packet_type)
    end
end

local function handle_unsequenced(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.unsequenced_packet, data)
    offset = offset + 1

    local packet_type = buffer(offset, 2):string()
    if packet_type == "N1" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.new_order, buffer(offset, packet_length-offset))
        process_new_order(buffer, item, offset, packet_length)
    elseif packet_type == "NR" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.new_order_response, buffer(offset, packet_length-offset))
        process_new_order_response(buffer, item, offset, packet_length)
    elseif packet_type == "M1" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.modify_order, buffer(offset, packet_length-offset))
        process_modify_order(buffer, item, offset, packet_length)
    elseif packet_type == "MR" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.modify_order_response, buffer(offset, packet_length-offset))
        process_modify_order_response(buffer, item, offset, packet_length)
    elseif packet_type == "CO" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.cancel_order, buffer(offset, packet_length-offset))
        process_cancel_order(buffer, item, offset, packet_length)
    elseif packet_type == "CR" then
        offset = offset + 2
        local item = subtree:add(ESesM.fields.cancel_order_response, buffer(offset, packet_length-offset))
        process_cancel_order_response(buffer, item, offset, packet_length)
    else
        local item = subtree:add(ESesM.fields.new_order, buffer(offset, packet_length-offset))
        item:add_proto_expert_info(e_undecoded, "Unexpected unsequenced packet type: " .. packet_type)
    end
end

LoginManager = {
    number_of_matching_engines = nil
}

local function handle_login(buffer, subtree, offset, packet_length)  
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.login, data)
    offset = offset + 1

    subtree:add(ESesM.fields.version, buffer(offset, 5))
    offset = offset + 5
    subtree:add(ESesM.fields.username, buffer(offset, 5))
    offset = offset + 5
    subtree:add(ESesM.fields.computer_id, buffer(offset, 8))
    offset = offset + 8
    subtree:add(ESesM.fields.application_protocol, buffer(offset, 8))    
    offset = offset + 8

    LoginManager.number_of_matching_engines = buffer(offset, 1):le_uint()
    subtree:add_le(ESesM.fields.number_of_matching_engines, buffer(offset, 1))    
    offset = offset + 1
end

local function handle_login_response(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.login_response, data)
    offset = offset + 1

    local number_of_matching_engines = buffer(offset, 1):le_uint()    
    local item = subtree:add_le(ESesM.fields.number_of_matching_engines, buffer(offset, 1))    
    if number_of_matching_engines ~= LoginManager.number_of_matching_engines then 
        item:add_proto_expert_info(e_undecoded, "Mismatch number of number of matching engines")
    end
    offset = offset + 1

    process_status_login(buffer, subtree, offset)
    offset = offset + 1
end

local function handle_synchronization_complete(buffer, subtree, offset, packet_length)
    local data = buffer(offset, packet_length-offset)
    subtree:add(ESesM.fields.synchronization_complete, data)
    offset = offset + 1
    subtree:add_le(ESesM.fields.number_of_matching_engines, buffer(offset, 1))    
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

-- Dissector entry point
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
    subtree:add_le(ESesM.fields.packet_length, buffer(offset, 2))
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
