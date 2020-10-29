do
    local melsec_proto = Proto("MELSEC", "MELSEC Protolcol")
    local melsec_sub_title = ProtoField.bytes("melsec.subtitle", "Sub Title", base.NONE)
    local melsec_network_code = ProtoField.bytes("melsec.networkcode", "Network Code", base.NONE)
    local melsec_PLC_NO = ProtoField.uint8("melsec.PLCNo", "PLC NO", base.DEC)
    local melsec_requested_module_IO_code = ProtoField.uint16("melsec.requested_module_io_code", "Requested Module IO Code", base.DEC)
    local melsec_requested_module_station_code = ProtoField.bytes("melsec.requested_module_station_code", "Requested Module Station Code", base.NONE)
    local melsec_requested_data_len = ProtoField.uint16("melsec.requested_data_len", "Requested Data Length", base.DEC)
    local melsec_cpu_monitor_timer = ProtoField.uint16("melsec.cpu_monitor_timer", "CPU Monitor Timer", base.DEC)
    local melsec_command = ProtoField.bytes("melsec.command", "command", base.NONE)
    local melsec_sub_command = ProtoField.bytes("melsec.sub_commnad", "Sub Command", base.NONE)
    local melsec_data_content = ProtoField.bytes("melsec.data_content", "Data Content", base.NONE)


    -- 将字段添加都协议中
    melsec_proto.fields = {
        melsec_sub_title,
        melsec_network_code,
        melsec_PLC_NO,
        melsec_requested_module_IO_code,
        melsec_requested_module_station_code,
        melsec_requested_data_len,
        melsec_cpu_monitor_timer,
        melsec_command,
        melsec_sub_command,
        melsec_data_content
    }

    --[[
        下面定义 melsec 解析器的主函数，这个函数由 wireshark调用
        第一个参数是 Tvb 类型，表示的是需要此解析器解析的数据
        第二个参数是 Pinfo 类型，是协议解析树上的信息，包括 UI 上的显示
        第三个参数是 TreeItem 类型，表示上一级解析树
    --]]
    function melsec_proto.dissector(tvb, pinfo, treeitem)

        

        -- 下面是想该根节点上添加子节点，也就是自定义协议的各个字段
        -- 注意 range 这个方法的两个参数的意义，第一个表示此时的偏移量
        -- 第二个参数代表的是字段占用数据的长度
        if (((tvb(0, 1):uint() == 80) and (tvb(1, 1):uint() == 0)) or ((tvb(0, 1):uint() == 208) and (tvb(1, 1):uint() == 0))) then
            -- 设置一些 UI 上面的信息
            pinfo.cols.protocol:set("MELSEC")
        

            if (tvb(0, 1):uint() == 80) and (tvb(1, 1):uint() == 0) then
                pinfo.cols.info:set("Request Command="..tvb:bytes(12, 1):tohex()..tvb:bytes(11, 1):tohex().." SubCommand="..tvb:bytes(14, 1):tohex()..tvb:bytes(13, 1):tohex())
            else
                pinfo.cols.info:set("Response")
            end

            local offset = 0
            local tvb_len = tvb:len()

            -- 在上一级解析树上创建 melsec 的根节点
            local melsec_tree = treeitem:add(melsec_proto, tvb:range(offset))
            melsec_tree:add(melsec_sub_title, tvb:range(offset, 2))
            offset = offset + 2
            melsec_tree:add(melsec_network_code, tvb:range(offset, 1))
            offset = offset + 1
            melsec_tree:add_le(melsec_PLC_NO, tvb:range(offset, 1))
            offset = offset + 1
            melsec_tree:add_le(melsec_requested_module_IO_code, tvb:range(offset, 2))
            offset = offset + 2
            melsec_tree:add(melsec_requested_module_station_code, tvb:range(offset,  1))
            offset = offset + 1
            melsec_tree:add_le(melsec_requested_data_len, tvb:range(offset, 2))
            offset = offset + 2 
            melsec_tree:add_le(melsec_cpu_monitor_timer, tvb:range(offset, 2))
            offset = offset + 2
            melsec_tree:add_le(melsec_command, tvb:range(offset, 2))
            offset = offset + 2
            melsec_tree:add(melsec_sub_command, tvb:range(offset, 2))
            offset = offset + 2
            melsec_tree:add(melsec_data_content, tvb:range(offset, tvb_len - offset))
        end
    end

    -- 向 wireshark 注册协议插件被调用的条件
    local tcp_port_table = DissectorTable.get("tcp.port")
    -- 改成你想要监听的端口
    tcp_port_table:add(1581, melsec_proto)
    -- 改成你想要监听的端口
    tcp_port_table:add(61022, melsec_proto)
end