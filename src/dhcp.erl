-module(dhcp).
-author(lweiyan@gmail.com).
-export([start/0, stop/0, ip_to_tpl/1]).

start() ->
    application:start(sasl),
    application:start(compiler),
    application:start(syntax_tools),
    application:start(lager),
    application:start(dhcp).

stop() ->
    application:stop(dhcp).

ip_to_tpl(I) ->
    <<A:8/integer, B:8/integer, C:8/integer, D:8/integer>> = <<I:32/integer>>,
    {A, B, C, D}.
