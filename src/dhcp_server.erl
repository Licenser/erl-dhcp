-module (dhcp_server).
-author(lweiyan@gmail.com).
-behaviour (gen_server).

-export ([start_link/0]).
-export ([init/1]).
-export ([handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include ("dhcp.hrl").
-record (dhcp_state, {socket, cb_mod, server}).

%%=======================
%% Gen_Server Callbacks
%%=======================

start_link () ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init ([]) ->
    {ok, Server} = application:get_env(server),
    {ok, M} = application:get_env(callback),
    lager:info("Starting DHCP server on IP ~p with callback ~p", [Server, M]),
    {ok, Socket} = gen_udp:open(67, [binary,
                                     inet,
                                     %{ip, Server},
                                     {broadcast, true},
                                     {reuseaddr, true}]),
    {ok, #dhcp_state{socket = Socket, server = Server, cb_mod = M}}.

handle_call (_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast (_Request, State) ->
    {noreply, State}.

handle_info ({udp, Socket, _IP, 68, Packet}, State = #dhcp_state{socket=Socket}) ->
    case dhcpparse:decode_packet(Packet) of
        {ok, DecodedPacket} ->
            case process_packet(DecodedPacket, State) of
                {ok, NewState} ->
                    {noreply, NewState};
                {error, Reason} ->
                    lager:error("Failed to process packet: ~p~n", [Reason]),
                    {noreply, State}
            end;
        {error, Reason} ->
            lager:error("Failed to decode packet: ~p~n", [Reason]),
            {noreply, State}
    end;
handle_info(Info, State) ->
    lager:debug("unknown package: ~p", [Info]),
    {noreply, State}.

terminate (_Reason, _State) ->
    ok.

code_change (_OldVsn, State, _Extra) ->
    {ok, State}.

process_packet(Packet = #dhcp_packet{msg_type = discover}, State) ->
    dhcpparse:print_packet(Packet),
    case get_leaseinfo(Packet, State) of
        {ok, LeaseInfo} ->
            ReplyPacket = offer_packet(Packet#dhcp_packet.xid, LeaseInfo, State),
            dhcpparse:print_packet(ReplyPacket),
            send_packet(ReplyPacket, State);
        {error, Reason} ->
            lager:error("Got discover error from get_leaseinfo: ~p~n", [Reason])
    end,
    {ok, State};

process_packet(Packet = #dhcp_packet{msg_type = request}, State) ->
    dhcpparse:print_packet(Packet),
    case get_leaseinfo(Packet, State) of
        {ok, LeaseInfo} when (LeaseInfo#dhcp_lease.ip_addr =:= Packet#dhcp_packet.requested_ip) or
                             ((Packet#dhcp_packet.requested_ip =:= {0, 0, 0, 0}) and (LeaseInfo#dhcp_lease.ip_addr =:= Packet#dhcp_packet.ciaddr)) ->
            ReplyPacket = ack_packet(Packet#dhcp_packet.xid, LeaseInfo, State),
            dhcpparse:print_packet(ReplyPacket),
            send_packet(ReplyPacket, State);
        {ok, _} ->
            ReplyPacket = nak_packet(Packet, State),
            dhcpparse:print_packet(ReplyPacket),
            send_packet(ReplyPacket, State);
        {error, Reason} ->
            lager:error("Got error from get_leaseinfo: ~p - sending nak~n", [Reason]),
            ReplyPacket = nak_packet(Packet, State),
            dhcpparse:print_packet(ReplyPacket),
            send_packet(ReplyPacket, State)
    end,
    {ok, State};

process_packet(Packet, State) ->
    lager:info("Other packet: ~p, ignoring!~n", [Packet#dhcp_packet.msg_type]),
    dhcpparse:print_packet(Packet),
    {ok, State}.

send_packet(Packet, State) ->
    case dhcpparse:encode_packet(Packet) of
        {ok, EncPacket} ->
            DestAddr = dest_addr(Packet),
            lager:info("Sending packet to: ~p / ~p~n", [DestAddr, 68]),
            case gen_udp:send(State#dhcp_state.socket, DestAddr, 68, EncPacket) of
                ok -> {ok, State};
                {error, Reason} when (Reason =:= ehostdown) or (Reason =:= ehostunreach) ->
                    lager:error("Got ~p, switching to broadcast~n", [Reason]),
                    case gen_udp:send(State#dhcp_state.socket, {255, 255, 255, 255}, 68, EncPacket) of
                        ok -> {ok, State};
                        {error, Reason} ->
                            lager:error("Got error from gen_udp:send -> ~p~n", [Reason]),
                            {ok, State}
                    end;
                {error, Reason} ->
                    lager:error("Got error from gen_udp:send -> ~p~n", [Reason]),
                    {ok, State}
            end;
        {error, Reason} ->
            lager:error("Failed to encode packet: ~p~n", [Reason]),
            {ok, State}
    end.

%% If we need to support DHCP relays, add checking for giaddr
dest_addr(Packet) when Packet#dhcp_packet.flags band 16#8000 ->
    {255, 255, 255, 255};
dest_addr(Packet) when (Packet#dhcp_packet.msg_type =:= offer) or (Packet#dhcp_packet.msg_type =:= nak) ->
    {255, 255, 255, 255};
dest_addr(Packet) when Packet#dhcp_packet.ciaddr =:= {0, 0, 0, 0} ->
    {255, 255, 255, 255};
dest_addr(Packet) ->
    Packet#dhcp_packet.ciaddr.

offer_packet(Xid, LeaseInfo, _State = #dhcp_state{server = Server}) ->
    #dhcp_packet{
       msg_type = offer,
       op = 2,
       htype = 1,
       hlen = 6,
       xid = Xid,
       yiaddr = LeaseInfo#dhcp_lease.ip_addr,
       siaddr = Server,
       chaddr = LeaseInfo#dhcp_lease.chaddr,
       options = [{message_type, offer}, {server_id, Server}] ++ LeaseInfo#dhcp_lease.options
      }.

ack_packet(Xid, LeaseInfo, _State = #dhcp_state{server = Server}) ->
    #dhcp_packet{
       msg_type = ack,
       op = 2,
       htype = 1,
       hlen = 6,
       xid = Xid,
       yiaddr = LeaseInfo#dhcp_lease.ip_addr,
       siaddr = Server,
       chaddr = LeaseInfo#dhcp_lease.chaddr,
       options = [{message_type, ack}, {server_id, Server}] ++ LeaseInfo#dhcp_lease.options
      }.

nak_packet(Packet, _State = #dhcp_state{server = Server}) ->
    #dhcp_packet{
       msg_type = nak,
       op = 2,
       htype = 1,
       hlen = 6,
       xid = Packet#dhcp_packet.xid,
       siaddr = Server,
       chaddr = Packet#dhcp_packet.chaddr,
       options = [{message_type, nak}, {server_id, Server}]
      }.

get_leaseinfo(Packet, _State = #dhcp_state{cb_mod = M}) ->
    case M:get_net_info(Packet#dhcp_packet.chaddr) of
        undefined ->
            {error, no_lease};
        {Network,
         GW, %{192, 168, 2, 1}
         Mask, %{255, 255, 255, 0}
         DNS, %{192, 168, 2, 1}
         Domain, %"danw.org"
         IP} ->
            Broadcast = Network + (bnot Mask), %{192, 168, 2, 255}

            {ok, #dhcp_lease{
                    ip_addr = IP,
                    chaddr = Packet#dhcp_packet.chaddr,
                    options = [{lease_time, 3600}, % One hour
                               {renewal_time, 1800}, % Thirty minutes
                               {rebinding_time, 3000},
                               {subnet_mask, ip_to_tpl(Mask)},
                               {broadcast_address, ip_to_tpl(Broadcast)},
                               {dns_server, ip_to_tpl(DNS)},
                               {domain_name, list_to_binary(Domain)},
                               {router, ip_to_tpl(GW)}
                              ]
                   }}
    end.


ip_to_tpl(I) ->
    <<A:8/integer, B:8/integer, C:8/integer, D:8/integer>> = <<I:32/integer>>,
    {A, B, C, D}.

%%tpl_to_ip({A, B, C, D}) ->
%%    <<I:32/integer>> = <<A:8/integer, B:8/integer, C:8/integer, D:8/integer>>,
%%    I.
%% case Packet#dhcp_packet.chaddr of
%%      {0, 16#1c, 16#b3, 16#ff, 16#5d, 16#d0} -> % Desktop
%%          {192, 168, 1, 109};
%%      {0, 16#12, 16#5A, 16#AA, 16#26, 16#EC} -> % XBox
%%          {192, 168, 1, 136};
%%      {0, 16#26, 16#8, 16#76, 16#de, 16#98} -> % iPhone 3GS
%%          {192, 168, 1, 3};
%%      {0, 16#16, 16#cb, 16#bf, 16#82, 16#dd} -> % Dallas Work
%%          {192, 168, 1, 5};
%%      {0, 28, 179, 106, 228, 75} -> % iPhone
%%          {192, 168, 1, 6};
%%      {0,30,194,185,233,41} -> % Dallas Laptop
%%          {192, 168, 1, 7};
%%      {0,30,194,185,233,42} -> % Dallas Laptop
%%          {192, 168, 1, 8};
%%      {0, 16#0c, 16#29, 16#31, 16#c7, 16#4a} -> % Work Laptop
%%          {192, 168, 2, 10};
%%      _ ->
%%          case lists:keysearch(requested_ip_address, 1, Packet#dhcp_packet.options) of
%%              {value, {requested_ip_address, TempIP}} -> TempIP;
%%              _ -> false
%%          end
%%  end,
