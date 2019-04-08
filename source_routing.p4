header_type easyroute_head_t 
{
	fields {
		premble : 64;
		num_valid : 32;
	}
}

header easyroute_head_t easyroute_head;

header_type eastroute_port_t 
{
	fields {
		port : 8;
	}
}

header eastroute_port_t eastroute_port;


parser start 
{
    // TODO
    return select(current(0,64))
    {
        0 : parse_head;
        default : ingress;
    }
}

parser parse_head
{
    extract(easyroute_head);
    return select(latest.num_valid)
    {
        0 : ingress;
        default : parse_port;
    }
}


parser parse_port
{
    extract(eastroute_port);
    return ingress;
}

action _drop() {
    drop();
}

action route() {
    modify_field(standard_metadata.egress_spec, eastroute_port.port);
    add_to_field(easyroute_head.num_valid,-1);
    remove_header(eastroute_port);
}

table route_pkt
{
    reads
    {
        eastroute_port : valid;
    }
    actions
    {
        _drop;
        route;
    }
}

control ingress 
{
    apply(route_pkt);
}

control egress 
{
    
}