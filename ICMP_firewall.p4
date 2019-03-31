#define ETHERTYPE_IPV4 0x0800
#define PROTOCOL_ICMP 0x01

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
header_type cnt_metadata_t
{
    fields
    {
        bit<6>cnt;                  //计数50个icnp包
    }
}


//header实例化
header header_ethernet_t header_ethernet;
header header_ipv4_t header_ipv4;
metadata cnt_metadata_t cnt_metadata;

//parser
parser start
{
    return parse_ethernet;
}
parser parse_ethernet
{
    extract(header_ethernet);
    return select(header_ethernet.ethertype)
    {
        ETHERTYPE_IPV4 : parse_ipv4;
        default : ingress;
    }
}
parser parse_ipv4
{
    extract(header_ipv4);
    return ingress;
}

register drop_triger
{
    width : 6;
    instance_count : 1;
}
action update_metadata()
{
    modify_field(cnt_metadata.cnt,drop_triger[0]);
    modify_field(cnt_metadata.cnt,cnt_metadata.cnt + 1);
    modify_field(drop_triger[0],cnt_metadata.cnt);
}
action forward_normal(in bit<9> port)
{
    modify_field(standard_metadata.egress_spec,port);
}
action _drop()
{
    drop();
}
table update_table
{
    actions
    {
        update_metadata;
    }
}
table forward_table_1
{
    reads
    {
        header_ipv4.dstAddr : lpm;
    }
    actions
    {
        forward_normal;
    }
}
table forward_table_2
{
    reads
    {
        header_ipv4.dstAddr : lpm;
    }
    actions
    {
        forward_normal;
    }
}
table drop_table
{
    actions
    {
        _drop;
    }
}
control ingress
{
    if(header_ipv4.protocol == PROTOCOL_ICMP)
    {
        apply(update_table);
        if(cnt_metadata.cnt >= 50)
        {
            apply(drop_table);
        }
        else
        {
            apply(forward_table_1);
        }
    }
    else
    {
        apply(forward_table_2);
    }
}
control egress
{

}

/*
table_set_default update_table update_metadata
table_set_default drop_table _drop
table_add forward_table_1 forward_normal 10.0.0.10/32 => 1
table_add forward_table_1 forward_normal 10.0.1.10/32 => 2
table_add forward_table_2 forward_normal 10.0.0.10/32 => 1
table_add forward_table_2 forward_normal 10.0.1.10/32 => 2
*/

























