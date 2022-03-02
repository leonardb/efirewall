-module(efirewall_test).

-include_lib("eunit/include/eunit.hrl").

efw_v4_test_() ->
    NotAllowed  = {{192, 168, 100, 0}, 24},
    Allowed     = {{192, 168, 101, 0}, 24},
    efirewall:new(test_fw),
    ok = efirewall:add(test_fw, [{{{192, 168, 100, 0}, 24}, <<"reserved_ip">>}]),
    [?_assert(pass =:= do_test_range(<<"reserved_ip">>, NotAllowed)),
        ?_assert(pass =:= do_test_range(not_found, Allowed))].

efw_v6_test_() ->
    NotAllowed = [{{10758,39104,13824,0,0,0,0,0}, 125},
        {{10758,39104,13824,0,0,0,16,0}, 125}],
    efirewall:new(test_fw),
    ok = efirewall:add(test_fw, [{R, <<"reserved_ip">>} || R <- NotAllowed]),
    [?_assert(pass =:= do_test_range(<<"reserved_ip">>, lists:nth(1, NotAllowed))),
        ?_assert(pass =:= do_test_range(<<"reserved_ip">>, lists:nth(2, NotAllowed)))].

do_test_range(Required, {{_, _, _, _} = Ip, MaskBits}) ->
    IpsInMask = ips_in_mask(MaskBits, 32),
    do_test_range(Required, 0, IpsInMask, Ip);
do_test_range(Required, {{_, _, _, _, _, _, _, _} = Ip, MaskBits}) ->
    IpsInMask = ips_in_mask(MaskBits, 128),
    do_test_range(Required, 0, IpsInMask, Ip).

do_test_range(_, IpsInMask, IpsInMask, _) ->
    pass;
do_test_range(Required, X, IpsInMask, {A, B, C, D} = Ip0) ->
    Ip = efirewall:long2ipv4(efirewall:ip2long(Ip0) + X),
    case efirewall:lookup(test_fw, Ip) of
        Required ->
            do_test_range(Required, X + 1, IpsInMask, {A, B, C, D});
        Failed ->
            {failed, io_lib:format("Expected ~p received ~p for ~p", [Required, Failed, Ip])}
    end;
do_test_range(Required, X, IpsInMask, {A, B, C, D, E, F, G, H} = Ip0) ->
    Ip = efirewall:long2ipv6(efirewall:ip2long(Ip0) + X),
    case efirewall:lookup(test_fw, Ip) of
        Required ->
            do_test_range(Required, X + 1, IpsInMask, {A, B, C, D, E, F, G, H});
        Failed ->
            {failed, io_lib:format("Expected ~p received ~p for ~p", [Required, Failed, Ip])}
    end.

ips_in_mask(MaskBits, MaxBits) ->
    round(math:pow(2, (MaxBits - MaskBits))).
