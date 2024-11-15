local ESesM = Proto("ESesM", "MIAX ESesM protocol")
local f = ESesM.fields

-- Header fields
f.packet_length = ProtoField.int32("ESesM.packet_length", "packetLength", base.DEC)
f.packet_type = ProtoField.string("ESesM.packet_type", "packetType", base.ASCII)

-- Dissector function
function ESesM.dissector(buffer, pinfo, tree)
end

-- Register the protocol dissector
local tcp_port = 41010 
DissectorTable.get("tcp.port"):add(tcp_port, ESesM)
