-module(dhcp).
-author(lweiyan@gmail.com).
-export([start/0, stop/0]).

start() ->
    application:start(sasl),
    application:start(lager),
    application:start(dhcp).

stop() ->
    application:stop(dhcp).
