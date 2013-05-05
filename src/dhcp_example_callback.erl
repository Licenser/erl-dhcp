-module(dhcp_example_callback).
-export([get_net_info/1]).

get_net_info(_CHAddr) ->

    Network = 16#C0A80200,
    GW = 16#C0A80201,
    Mask = 16#FFFFFF00,
    DNS = GW,
    Domain = "test.local",
    IP = 16#C0A80202,
    {Network,
     GW, %{192, 168, 2, 1}
     Mask, %
     DNS, %{192, 168, 2, 1}
     Domain, %"danw.org"
     IP}.
