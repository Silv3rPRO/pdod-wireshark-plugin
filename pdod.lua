-- pdod protocol
pdod_proto = Proto("pdod","Pokemon Dawn of Darkness")

clientToServerPacketInfos = {
	 {"c",     "Garbage?"},
	 {"[205]", "Client Version"},
	 {"[253]", "Authentication"},
	 {"^", "Disconnect request"},
	 {"[240]", "Chat message"},
	 {"b", "Ping"},						-- every 10 seconds (10 seconds after pong)
	 {"[239]", "Server Pong"},
	 {"[207]", "Send Movement"},		-- every 0.2 seconds
	 {"[232]", "Send Direction"},
	 {"[237]", "Interact"},
	 {"[202]", "Use Battle Move"},
	 {"[191]", "Battle Run"},
	 {"[215]", "Battle Switch Pokemon"},
	 {"x", "Request Player Info"},
	 {"[179]", "Server Time???"},		-- send the server time once every 5 minutes
	 {"\\", "Use Surf"}
}

serverToClientPacketInfos = {
	 {"c",     "Garbage?"},
	 {"[205]", "Request Version"},
	 {"[249]", "Version OK"},
	 {"[251]", "Authentication OK"},
	 {"[252]", "Authentication Failure"},
	 {"[185]", "System message"},
	 {"^", "Disconnected"},
	 {"[240]", "Chat message"},
	 {"b", "Pong"},
	 {"[239]", "Server Ping"},
	 {"[236]", "Dialog Message"},
	 {"g", "NPC Movement"},
	 {"[233]", "Interacting"},
	 {"[238]", "NPC List"},
	 {"[231]", "Player Update"},
	 {"[204]", "Battle Message"},
	 {"[228]", "Position Updated"},
	 {"[225]", "Map Changed"},			-- O[x?][y?][map id]
	 {"x", "Player Info"},
	 {"e", "Pokemon EV Gained"},
	 {"[207]", "Player Movement"},
	 {"[230]", "Player Leave"},
	 {"f", "Triple f???"}
}

local PACKET_END = "#"

function bindPacket(packetList, data)
	 local index = 1
	 local headersFound = {}
	 
	 while true do
			local matchStart, matchEnd, packet = data.pdodData:find("(.-" .. PACKET_END .. ")", index)
			if packet == nil then break end
			if isHex(string.byte(packet, 1)) then
				data.tree:add(packet)
				local localPacketFound = false
				for i, packetInfo in ipairs(packetList) do
					 if packet:find(packetInfo[1], 1, true) == 4 then
						if headersFound[packetInfo[2]] == nil then
							 headersFound[packetInfo[2]] = 0
						end
						headersFound[packetInfo[2]] = headersFound[packetInfo[2]] + 1
						localPacketFound = true
						break
					 end
				end
				if localPacketFound == false then
					 if headersFound["UNKNOWN"] == nil then
							headersFound["UNKNOWN"] = 0
					 end
					 headersFound["UNKNOWN"] = headersFound["UNKNOWN"] + 1
				end
			end
			index = matchEnd + 1
	 end

	 index = 1
	 for headerName, headerCount in pairs(headersFound) do
			if index ~= 1 then
				 data.infoField = data.infoField .. "|"
			end
			data.infoField = data.infoField .. headerName
			if headerCount > 1 then
				 data.infoField = data.infoField .. [[(x]] .. headerCount .. [[)]]
			end
			index = index + 1
	 end
end

local SEND_KEY = {0x53, 0x57, 0x73, 0x64, 0x38, 0x66, 0x68, 0x73, 0x53, 0x47, 0x4A, 0x59, 0x55, 0x4A, 0x36, 0x35, 0x39, 0x30, 0x35, 0x34, 0x36, 0x6A, 0x34, 0x6A, 0x66, 0x6A, 0x72, 0x6A, 0x68, 0x33, 0x34, 0x37, 0x39, 0x76, 0x6D, 0x62, 0x20, 0x62, 0x70, 0x64, 0x66, 0x38, 0x65, 0x64, 0x39, 0x72, 0x66, 0x38, 0x30, 0x39, 0x33, 0x34, 0x74, 0x72, 0x5F, 0x5F, 0x3D, 0x2D, 0x38, 0x39, 0x35, 0x36, 0x35, 0x36, 0x67, 0x66, 0x73, 0x64, 0x66, 0x53, 0x44, 0x73, 0x66}
local RECV_KEY = {0x3C, 0x47, 0x47, 0x66, 0x64, 0x6C, 0x37, 0x6C, 0x37, 0x6C, 0x35, 0x54, 0x48, 0x3A, 0x40, 0x27, 0x23, 0x27, 0x23, 0x44, 0x46, 0x47, 0x4E, 0x2E, 0x2C, 0x2E, 0x2C, 0x2E, 0x2E, 0x35, 0x34, 0x34, 0x35, 0x36, 0x30, 0x39, 0x64, 0x66, 0x6A, 0x68, 0x52, 0x45, 0x47, 0x46, 0x45, 0x4A, 0xA3, 0x24, 0x72, 0x20, 0x34, 0x33, 0x35, 0x33, 0x24, 0x20, 0x45, 0x46, 0x47, 0x67, 0x79, 0x74, 0x6C, 0x6B, 0x6A, 0x64, 0x66, 0x67, 0x38, 0x6F, 0x20, 0xA3, 0x4F}

function isHex(c)
	return (c >= 48 and c <= 57) or (c >= 65 and c <= 70)
end

function pdod_proto.dissector(buffer,pinfo,tree)
	 pinfo.cols.protocol = "PDOD"
	 
	 local data = {
			buffer = buffer,
			pinfo = pinfo,
			pdodData = "",
			tree = tree:add(pdod_proto, buffer(), "PDOD Protocol"),
			infoField = ""
	 }

	 
	local key = SEND_KEY
	local keyLen = 73
	if pinfo.src_port == 10203 then
		key = RECV_KEY
		keyLen = 72
	end
	
	local index = 0
	while index < keyLen do
		local bc1 = bit.bxor(buffer(0, 1):uint(), key[index + 1])
		local bc2 = bit.bxor(buffer(1, 1):uint(), key[(index + 1) % keyLen + 1])
		local bc3 = bit.bxor(buffer(2, 1):uint(), key[(index + 2) % keyLen + 1])
		local ec = bit.bxor(buffer(buffer:len() - 1, 1):uint(), key[(index + buffer:len() - 1) % keyLen + 1])
		if isHex(bc1) and isHex(bc2) and isHex(bc3) and ec == 35 then
			local hexSize = string.char(bc1) .. string.char(bc2) .. string.char(bc3)
			local size = tonumber(hexSize, 16)
			if size <= buffer:len() - 4 then
				local iec = bit.bxor(buffer(size + 3, 1):uint(), key[(index + size + 3) % keyLen + 1])
				if iec == 35 then
					break
				end
			end
		end
		index = index + 1
	end
	
	local foundIndex = index
	
	local i = 0	
	while i < buffer:len() do
		local c = bit.bxor(buffer(i,1):uint(), key[(index % keyLen) + 1])
		if c >= 32 and c < 128 then
			data.pdodData = data.pdodData .. string.char(c)
		else
			data.pdodData = data.pdodData .. "[" .. c .. "]"
		end
		i = i + 1
		index = index + 1
	end
	 
	 if pinfo.src_port == 10203 then
			data.infoField = "[s]"
			data.tree:add(buffer(0,buffer:len()), "server -> client")
			data.tree:add(buffer(0,buffer:len()), data.pdodData)
			bindPacket(serverToClientPacketInfos, data)
	 else
			data.infoField = "[c]"
			data.tree:add(buffer(0,buffer:len()), "client -> server")
			data.tree:add(buffer(0,buffer:len()), data.pdodData)
			bindPacket(clientToServerPacketInfos, data)
	 end
	 pinfo.cols.info = data.infoField
end

tcp_table = DissectorTable.get("tcp.port")

tcp_table:add(10203, pdod_proto)
