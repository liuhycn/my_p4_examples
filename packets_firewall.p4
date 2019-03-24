header_type ethernet_t
{
    fields
    {
        bit<48>dst;
    }
}

header_type recorder_t
{
    fields
    {
        bit<6>cnt;
    }
}

metadata recorder_t recorder;

header ethernet_t ethernet;

parser start
{
    return parse_ethernet;
}

parser parse_ethernet
{
    extract(ethernet);
    return ingress;
}

register drop_triger
{
    width : 6;
    instance_count : 1;
}

action _drop()
{
    drop();
}
action forward_h2_h1()
{
    modify_field(standard_metadata.egress_spec, 1);

}
action get_value()
{
    modify_field(recorder.cnt, drop_triger[0]);
}
action forward_h1_h2()
{
    modify_field(standard_metadata.egress_spec, 2);
    drop_triger[0] = drop_triger[0] + 1;
}
table h1_h2
{
    actions
    {
        forward_h1_h2;
    }
    size : 2;
}
table h2_h1
{
    actions
    {
        forward_h2_h1;
    }
    size : 2;
}

table drop_table
{
    actions
    {
        _drop;
    }
    size : 2;
}

control ingress
{
    get_value();
    if(recorder.cnt >= 50)
    {
        apply(drop_table);
    }
    else
    {
        if(standard_metadata.ingress_port == 1)
        {
            apply(h1_h2);
        }
        else
        {
            apply(h2_h1);
        }
    }
}
control egress
{
    
}
