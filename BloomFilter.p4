header_type header_ethernet_t
{
	fields
	{
		bit<48>dst;					//目的mac
		bit<48>src;					//源mac
		bit<16>ethertype;			//数据段协议类型
	}
}

header_type header_ipv4_t 
{
    fields {
        bit<4>version;   			//版本
        bit<4>ihl;					//头部长度
        bit<8>diffserv;				//区分服务
        bit<16>totalLen;			//总长度
        bit<16>identification;		//标识，主机计数器
        bit<3>flags;				//标志，分片使用
        bit<13>fragOffset;			//分片偏移
        bit<8>ttl;					//ttl
        bit<8>protocol;				//数据段协议类型
        bit<16>hdrChecksum;			//头部校验和
        bit<32>srcAddr;				//源IP
        bit<32>dstAddr;				//目的IP
    }
}

header_type header_tcp_t 
{
    fields 
    {
        bit<16>srcPort;
        bit<16>dstPort;
        bit<32>seqNo;
        bit<32>ackNo;
        bit<4>dataOffset;
        bit<3>res;
        bit<3>ecn;
        bit<6>ctrl;
        bit<16>window;
        bit<16>checksum;
        bit<16>urgentPtr;
    }
}

// header_type header_udp_t
// {
//     fields
//     {
//         bit<16>srcPort;
//         bit<16>dstPort;
//         bit<16>length;
//         bit<16>udpchecksum;
//     }
// }

header_type bf_metadata_t
{
    fields
    {
        bit<13>hash_val1;
        bit<13>hash_val2;
        bit<13>hash_val2;
        bit<1>bf_val1;
        bit<1>bf_val2;
        bit<1>bf_val3;
    }
}

header header_ethernet_t header_ethernet;

header header_ipv4_t header_ipv4;

header header_tcp_t header_tcp;

// header header_udp_t header_udp;

metadata bf_metadata_t bf_metadata;

//-------------------------------------------------//

parser start
{
    return parse_ethernet;
}

parser parse_ethernet
{
    extract(header_ethernet);
    return select(header_ethernet.ethertype)
    {
        0x0800 : ipv4;
        default : ingress;
    }
}

paeser parse_ipv4
{
    extract(header_ipv4);
    {
        return select(header_ipv4.protocol)
        {
            0x0006 : tcp;
            // 0x0011 : udp;
            default : ingress;
        }
    }
}

parser parse_tcp
{
    extract(header_tcp);
    {
        return ingress;
    }
}

// parser parse_udp
// {
//     extract()
// }

//-------------------------------------------------//

field_list hash_val
{
    header_ethernet.src;
    header_ipv4.srcAddr;
    header_tcp.srcPort;
}

//-------------------------------------------------//

field_list_calculation hash_function1
{
    input
    {
        hash_val;
    }
    algorithm : xor16;
    output_width : 13;
}

field_list_calculation hash_function2
{
    input
    {
        hash_val;
    }
    algorithm : csum16;
    output_width : 13;
}

field_list_calculation hash_function3
{
    input
    {
        hash_val;
    }
    algorithm : crc16;
    output_width : 13;
}

//-------------------------------------------------//

register bloom_filter
{
    width : 1;
    instance_count : 8192;
}

//-------------------------------------------------//

action _drop()
{
    drop();
}

action set_bf_metadata()
{
    modify_field_with_hash_based_offset(bf_metadata.hash_val1, 0, hash_function1, 8192);
    modify_field_with_hash_based_offset(bf_metadata.hash_val2, 0, hash_function2, 8192);
    modify_field_with_hash_based_offset(bf_metadata.hash_val3, 0, hash_function3, 8192);
    register_read(bf_metadata.bf_val1, bloom_filter, bf_metadata.hash_val1);
    register_read(bf_metadata.bf_val2, bloom_filter, bf_metadata.hash_val2);
    register_read(bf_metadata.bf_val3, bloom_filter, bf_metadata.hash_val3);
}

action basic_forward(in bit<9> port)
{
    modify_field(standard_metadata.egress_spec, port);
}

//-------------------------------------------------//

table bf_set
{
    actions
    {
        set_bf_metadata;
    }
    size : 512;
}


table bf_function
{
    reads
    {
        bf_metadata.bf_val1 : exact;
        bf_metadata.bf_val2 : exact;
        bf_metadata.bf_val3 : exact;
    }
    actions
    {
        no_op;
        _drop;
    }
    size : 512;
}

table forward
{
    reads
    {
        header_ipv4.dstAddr : lpm;
    }
    actions
    {
        basic_forward;
        _drop;
    }
}

control ingress
{
    apply(bf_set);
    apply(bf_function);
    apply(forward);
}

control egress
{
    //empty
}
















