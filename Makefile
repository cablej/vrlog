T=$(GOPATH)/src/github.com/google/trillian
R=.

trillian::
	go get -u -t -v github.com/google/trillian
	cd $T && \
	go build ./server/trillian_log_server && \
	go build ./server/trillian_log_signer && \
	go build ./server/trillian_map_server

tlserver::
	cd $T && ./trillian_log_server --logtostderr ...

tlsigner::
	cd $T && ./trillian_log_signer --logtostderr --force_master --http_endpoint=localhost:8092 --rpc_endpoint=localhost:8193 --batch_size=1000 --sequencer_guard_window=0 --sequencer_interval=200ms

createlog:: $R/logid

$R/logid:
	go run github.com/google/trillian/cmd/createtree --admin_server=localhost:8090 > $R/logid

deletelog::
	cd $T && go run cmd/deletetree/main.go --admin_server=localhost:8090 --log_id=`cat $R/logid`
	rm $R/logid

dump::
	go run dump/main.go --log_id=`cat logid` --register=statistical-geography

extract::
	go run extract/main.go --log_id=`cat logid`

tmserver::
	cd $T && ./trillian_map_server --logtostderr --rpc_endpoint=localhost:8095

createmap:: $R/mapid

$R/mapid:
	go run github.com/google/trillian/cmd/createtree --admin_server=localhost:8093  --tree_type=MAP --hash_strategy=TEST_MAP_HASHER  > $R/mapid

deletemap::
	cd $T && go run cmd/deletetree/main.go --admin_server=localhost:8090 --log_id=`cat $R/mapid`
	rm $R/mapid

mapper::
	go run vrlog.go --map_id=`cat mapid` --log_id=`cat logid`

extractmap::
	go run extractmap/main.go --map_id=`cat mapid` 0

extractmap_all::
	go run extractmap/main.go --map_id=`cat mapid`

webserver::
	go run webserver/main.go --map_id=`cat mapid`
