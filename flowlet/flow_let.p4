/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/intrinsic.p4"

#define FLOWLET_MAP_SIZE 13    // 8K
#define FLOWLET_INACTIVE_TOUT 50000 // usec -> 50ms

header_type ingress_metadata_t 
{
    fields 
    {
        flow_ipg : 32; //与上一个数据包的时间间隔
        flowlet_map_index : FLOWLET_MAP_SIZE; //对应流量的索引
        flowlet_id : 16; // 划分五元组之后的id
        flowlet_lasttime : 32; // 本条流量上一个数据包的时间戳

        ecmp_offset : 14; // offset into the ecmp table

        nhop_ipv4 : 32; //下一跳的ip地址
    }
}

metadata ingress_metadata_t ingress_metadata;

action _drop() 
{
    drop();
}

field_list l3_hash_fields                               //用五元组来区分流量，再根据时间区分
{
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
}

field_list_calculation flowlet_map_hash 
{
    input
    {
        l3_hash_fields;
    }
    algorithm : crc16;
    output_width : FLOWLET_MAP_SIZE;
}

register flowlet_lasttime 
{
    width : 32;
    instance_count : 8192;
}

register flowlet_id 
{
    width : 16;
    instance_count : 8192;
}


action lookup_flowlet_map()
{
    modify_field_with_hash_based_offset(ingress_metadata.flowlet_map_index, 0 ,flowlet_map_hash, FLOWLET_MAP_SIZE);
    //计算flow_let的偏移量

    register_read(ingress_metadata.flowlet_id,flowlet_id, ingress_metadata.flowlet_map_index);
    //从flow_id寄存器中读出当前的flow_id，存到元数据

    modify_field(ingress_metadata.flow_ipg,intrinsic_metadata.ingress_global_timestamp);
    //记录当前数据包的到达时间

    register_read(ingress_metadata.flowlet_lasttime,flowlet_lasttime, ingress_metadata.flowlet_map_index);
    //读出当前流量上一条数据包的到达时间

    subtract_from_field(ingress_metadata.flow_ipg,ingress_metadata.flowlet_lasttime);
    //计算时间差：本次和上一次

    register_write(flowlet_lasttime, ingress_metadata.flowlet_map_index,intrinsic_metadata.ingress_global_timestamp);
    //更新当前流量的最后一个数据包的到达时间，即记录本次数据包的到达时间

}

table flowlet 
{
    actions 
    {
        lookup_flowlet_map;
    }
}

action update_flowlet_id() 
{
    add_to_field(ingress_metadata.flowlet_id, 1);
    register_write(flowlet_id, ingress_metadata.flowlet_map_index,ingress_metadata.flowlet_id);
}

table new_flowlet 
{
    actions 
    {
        update_flowlet_id;
    }
}


//--------------------------ECMP---------------------------//

field_list flowlet_l3_hash_fields                       //ECMP 哈希列表
{
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    tcp.srcPort;
    tcp.dstPort;
    ingress_metadata.flowlet_id;
}

#define ECMP_BIT_WIDTH 10
#define ECMP_GROUP_TABLE_SIZE 1024
#define ECMP_NHOP_TABLE_SIZE 16384

field_list_calculation flowlet_ecmp_hash 
{
    input
    {
        flowlet_l3_hash_fields;
    }
    algorithm : crc16;
    output_width : ECMP_BIT_WIDTH;
}

action set_ecmp_select(ecmp_base, ecmp_count) 
{
    modify_field_with_hash_based_offset(ingress_metadata.ecmp_offset, ecmp_base,flowlet_ecmp_hash, ecmp_count);
    //ecmp_count代表哈希值的范围，计算的结果要对它取模
}


action set_nhop(nhop_ipv4, port)
{
    modify_field(ingress_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

table ecmp_group                                        //根据目的IP选择所属的ECMP组
{
    reads 
    {
        ipv4.dstAddr : lpm;
    }
    actions 
    {
        _drop;
        set_ecmp_select;
    }
    size : ECMP_GROUP_TABLE_SIZE;
}

table ecmp_nhop                                         //根据ecmp的offset来决定出端口和下一跳ip
{
    reads 
    {
        ingress_metadata.ecmp_offset : exact;
    }
    actions 
    {
        _drop;
        set_nhop;
    }
    size : ECMP_NHOP_TABLE_SIZE;
}

action set_dmac(dmac) 
{
    modify_field(ethernet.dstAddr, dmac);
}

table forward 
{
    reads 
    {
        ingress_metadata.nhop_ipv4 : exact;
    }
    actions 
    {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) 
{
    modify_field(ethernet.srcAddr, smac);
}

table send_frame 
{
    reads 
    {
        standard_metadata.egress_port: exact;
    }
    actions 
    {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

control ingress 
{
    apply(flowlet);
    if (ingress_metadata.flow_ipg > FLOWLET_INACTIVE_TOUT) 
    {
        apply(new_flowlet);
    }
    apply(ecmp_group);                      //计算ecmp哈希值
    apply(ecmp_nhop);
    apply(forward);
}

control egress 
{
    apply(send_frame);
}
