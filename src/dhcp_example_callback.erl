-module(dhcp_example_callback).
-export([get_net_info/1]).

get_net_info(CHAddr) ->
    lager:debug("DHCP request from: ~p", [CHAddr]),
    Network = 16#C0A80200,
    GW = 16#C0A80201,
    Mask = 16#FFFFFF00,
    DNS = GW,
    Domain = "test.local",
    IP = 16#C0A80202,
    Broadcast = Network + (bnot Mask), %{192, 168, 2, 255}
    [{ip, IP},
     {lease_time, 3600}, % One hour
     {renewal_time, 1800}, % Thirty minutes
     {rebinding_time, 3000},
     {subnet_mask, Mask},
     {broadcast_address, Broadcast},
     {dns_server, DNS},
     {domain_name, Domain},
     {router, GW}].

