-module(efirewall).

-export([lookup/2,
         new/1,
         flush/1,
         add/2,
         dump/1]).

-export([ip2long/1, long2ipv4/1, long2ipv6/1]).

-type fw_name()             :: atom().
-type cidr()                :: {inet:ipv4_address(), 0..32} |
                               {inet:ipv6_address(), 0..128}.
-type cidr_with_reason()    :: {cidr(), binary()}.

-export_type([fw_name/0,
              cidr_with_reason/0,
              cidr/0]).

-define(fw(FwName), persistent_term:get(FwName)).
-define(IPV4_FORMAT, "~8.2.0B~8.2.0B~8.2.0B~8.2.0B").
-define(IPV6_FORMAT, "~16.2.0B~16.2.0B~16.2.0B~16.2.0B~16.2.0B~16.2.0B~16.2.0B~16.2.0B").

%% @doc Create a new firewall
-spec new(fw_name()) -> ok.
new(FwName) ->
    persistent_term:put(FwName, trie:new()).

%% @doc Flush all data in an existing firewall
-spec flush(fw_name()) -> ok.
flush(FwName) ->
    new(FwName).

dump(FwName) ->
    [Res || {_, Res} <- trie:to_list(?fw(FwName))].

%% @doc Add CIDRs to a firewall
-spec add(fw_name(), [cidr_with_reason()]) -> ok.
add(FwName, Ranges) when is_atom(FwName) andalso is_list(Ranges) ->
    case persistent_term:get(FwName, missing) of
        missing ->
            {error, missing_firewall};
        FwData ->
            persistent_term:put(FwName, add_ranges(Ranges, FwData))
    end.

%% @doc Check if an IP address is blocked
-spec lookup(fw_name(), inet:ip_address()) -> not_found | binary().
lookup(FwName, {_, _, _, _} = Ip) ->
    do_lookup(FwName, Ip);
lookup(FwName, {_, _, _, _, _, _, _, _} = Ip) ->
    do_lookup(FwName, Ip);
lookup(FwName, IpBin) when is_binary(IpBin) ->
    {ok, IpTuple} = inet:parse_address(binary_to_list(IpBin)),
    lookup(FwName, IpTuple);
lookup(FwName, IpList) when is_list(IpList) ->
    {ok, IpTuple} = inet:parse_address(IpList),
    lookup(FwName, IpTuple).

do_lookup(FwName, Ip) ->
    {ok, Match} = mk_match(Ip),
    case trie:find_match(Match, ?fw(FwName)) of
        error ->
            not_found;
        {ok, _, {_Cidr, Reason}} ->
            Reason
    end.

add_ranges([], FwData) ->
    FwData;
add_ranges([{{{_, _, _, _}, _} = Cidr, Reason} = D | T], FwData) when is_binary(Reason) ->
    {ok, Key} = mk_key(Cidr),
    StoreRes = trie:store(Key, D, FwData),
    add_ranges(T, StoreRes);
add_ranges([{{{_, _, _, _, _, _, _, _}, _} = Cidr, Reason} = D | T], FwData) when is_binary(Reason) ->
    {ok, Key} = mk_key(Cidr),
    StoreRes = trie:store(Key, D, FwData),
    add_ranges(T, StoreRes).

mk_key({{A, B, C, D} = Ip, N}) ->
    case inet:ntoa(Ip) of
        {error,einval} = Err ->
            Err;
        _ ->
            X = io_lib:format(?IPV4_FORMAT, [A, B, C, D]),
            {ok, lists:sublist(X, N) ++ wildcard(N, 32)}
    end;
mk_key({{A, B, C, D, E, F, G, H} = Ip, N}) ->
    case inet:ntoa(Ip) of
        {error, einval} = Err ->
            Err;
        _ ->
            X = io_lib:format(?IPV6_FORMAT, [A, B, C, D, E, F, G, H]),
            {ok, lists:sublist(X, N) ++ wildcard(N, 128)}
    end.

mk_match({A, B, C, D} = Ip) ->
    case inet:ntoa(Ip) of
        {error, einval} = Err ->
            Err;
        _ ->
            {ok, io_lib:format(?IPV4_FORMAT, [A, B, C, D])}
    end;
mk_match({A, B, C, D, E, F, G, H} = Ip) ->
    case inet:ntoa(Ip) of
        {error,einval} = Err ->
            Err;
        _ ->
            {ok, io_lib:format(?IPV6_FORMAT, [A, B, C, D, E, F, G, H])}
    end.

wildcard(Mask, Mask) -> "";
wildcard(_Mask, _Bits) -> "*".

ip2long({B3, B2, B1, B0}) ->
    (B3 bsl 24) bor (B2 bsl 16) bor (B1 bsl 8) bor B0;
ip2long({W7, W6, W5, W4, W3, W2, W1, W0}) ->
    (W7 bsl 112) bor (W6 bsl 96) bor (W5 bsl 80) bor (W4 bsl 64) bor
        (W3 bsl 48) bor (W2 bsl 32) bor (W1 bsl 16) bor W0.

long2ipv6(I) ->
    %% ipv6
    B = lists:foldl(
          fun(1, []) ->
                  [{I bsr 16, I band 65535}];
             (O, [{H, _} | _] = Acc) ->
                  [{I bsr (16 * O), H band 65535} | Acc]
          end, [], lists:seq(1,8)),
    list_to_tuple([V || {_, V} <- B]).

long2ipv4(I) ->
    %% ipv4
    B = lists:foldl(
          fun(1, []) ->
                  [{I bsr 8, I band 255}];
             (O, [{H, _} | _] = Acc) ->
                  [{I bsr (8 * O), H band 255} | Acc]
          end, [], lists:seq(1,4)),
    list_to_tuple([V || {_, V} <- B]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

efw_v4_test_() ->
    NotAllowed  = {{192, 168, 100, 0}, 24},
    Allowed     = {{192, 168, 101, 0}, 24},
    new(test_fw),
    ok = add(test_fw, [{{{192, 168, 100, 0}, 24}, <<"reserved_ip">>}]),
    [?_assert(pass =:= do_test_range(<<"reserved_ip">>, NotAllowed)),
     ?_assert(pass =:= do_test_range(not_found, Allowed))].

efw_v6_test_() ->
    NotAllowed = [{{10758,39104,13824,0,0,0,0,0}, 125},
                  {{10758,39104,13824,0,0,0,16,0}, 125}],
    new(test_fw),
    ok = add(test_fw, [{R, <<"reserved_ip">>} || R <- NotAllowed]),
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
    Ip = long2ipv4(ip2long(Ip0) + X),
    case lookup(test_fw, Ip) of
        Required ->
            do_test_range(Required, X + 1, IpsInMask, {A, B, C, D});
        Failed ->
            {failed, io_lib:format("Expected ~p received ~p for ~p", [Required, Failed, Ip])}
    end;
do_test_range(Required, X, IpsInMask, {A, B, C, D, E, F, G, H} = Ip0) ->
    Ip = long2ipv6(ip2long(Ip0) + X),
    case lookup(test_fw, Ip) of
        Required ->
            do_test_range(Required, X + 1, IpsInMask, {A, B, C, D, E, F, G, H});
        Failed ->
            {failed, io_lib:format("Expected ~p received ~p for ~p", [Required, Failed, Ip])}
    end.

ips_in_mask(MaskBits, MaxBits) ->
    round(math:pow(2, (MaxBits - MaskBits))).

-endif.
