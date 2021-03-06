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
    SIAddr = case LeaseInfo#dhcp_lease.next_server of
                 undefined ->
                     Server;
                  Next ->
                     Next
             end,
    #dhcp_packet{
       msg_type = offer,
       op = 2,
       htype = 1,
       hlen = 6,
       xid = Xid,
       yiaddr = LeaseInfo#dhcp_lease.ip_addr,
       siaddr = SIAddr,
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
        Lease ->
            {ok, make_lease(#dhcp_lease{chaddr = Packet#dhcp_packet.chaddr}, [], Lease)}
    end.

make_lease(L, Opts, []) ->
    L#dhcp_lease{options = Opts};

make_lease(L, Opts, [{ip, IP} | R]) when is_integer(IP) ->
    make_lease(L, Opts, [{ip, dhcp:ip_to_tpl(IP)} | R]);
make_lease(L, Opts, [{ip, IP = {_,_,_,_}} | R]) ->
    make_lease(L#dhcp_lease{ip_addr = IP}, Opts, R);

make_lease(L, Opts, [{next_server, IP} | R]) when is_integer(IP) ->
    make_lease(L, Opts, [{next_server, dhcp:ip_to_tpl(IP)} | R]);
make_lease(L, Opts, [{next_server, IP = {_,_,_,_}} | R]) ->
    make_lease(L#dhcp_lease{next_server = IP}, Opts, R);

make_lease(L, Opts, [{K, V} | R]) ->
    make_lease(L, lists:keystore(K, 1, Opts, {K, V}), R).
