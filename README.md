efirewall
=====

A simple trie based IPv4/IPv6 firewall.

Internally the firewall trie is stored as a persistent term so concurrent updates are not supported.

Bulk addition of ranges can be performed through `efirewall:add(FwName, Ranges).`

```
-type fw_name() :: atom().
-type cidr()    :: {inet:ipv4_address(), 0..32} |
                   {inet:ipv6_address(), 0..128}.
-type entry()   :: {cidr(), accept | reject, binary()}.

%% @doc Add CIDRs to a firewall
-spec add(fw_name(), [entries()]) -> ok.

%% @doc Check if an IP address is blocked
-spec lookup(fw_name(), inet:ip_address()) -> not_found | {accept | reject, binary()}.
```

Build
-----

    $ rebar3 compile

Usage
-----

```erlang
1> FwName = my_firewall.
my_firewall
2> efirewall:new(FwName).
ok
3> efirewall:add(FwName, [{{{192,168,1,0},24}, reject, <<"reserved_range">>}]).
ok
4> efirewall:blocked(FwName, {192,168,1,100}).
{reject, <<"reserved_range">>}
5> efirewall:blocked(FwName, {192,168,2,100}).
not_found
```
