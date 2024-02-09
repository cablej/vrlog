package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/merkle/maphasher"
	"github.com/x/vrlog/helpers"

	"github.com/google/trillian/merkle/mapverifier"
	"google.golang.org/grpc"
)

var (
	trillianMap = flag.String("trillian_map", "localhost:8093", "address of the Trillian Map RPC server.")
	trillianLog = flag.String("trillian_log", "localhost:8090", "address of the Trillian Log RPC server.")
	mapID       = flag.Int64("map_id", 0, "Trillian MapID to write.")
	logID       = flag.Int64("log_id", 0, "Trillian LogID to write.")
	mapLogID    = flag.Int64("map_log_id", 0, "Trillian Map Log ID to write.")
	idKey       = flag.String("id_key", "secret1", "Key to use to generate ids. This should be a randomly generated 128-bit key.")
	encKey      = flag.String("enc_key", "secret2", "Key used to encrypt fields. This should be a randomly generated 128-bit key.")
	fieldsStr   = flag.String("fields", "id,firstName:32,lastName:32,dob,ssn", "Comma-separated list of fields to include in the voter record (and optionally including padded length).")
	testMode    = flag.Bool("testMode", false, "Test mode (enables batch voter API for testing, disable in production)")
	fields      = strings.Split(*fieldsStr, ",")
)

type Metadata struct {
	Version int           `json:"version"`
	History []HistoryItem `json:"history"`
}

type HistoryItem struct {
	Date      time.Time `json:"date"`
	EventType string    `json:"eventType"`
	Signature string    `json:"signature"`
	Signer    string    `json:"signer"`
}

type AppendOnlyProof struct {
	MapProof    trillian.GetSignedMapRootResponse       `json:"map_proof"`
	LogProof    trillian.GetLatestSignedLogRootResponse `json:"log_proof"`
	MapLogProof trillian.GetLatestSignedLogRootResponse `json:"map_log_proof"`
	Version     int64                                   `json:"version"`
}

type BatchVoterRequest struct {
	StartId int               `json:"start_id"`
	EndId   int               `json:"end_id"`
	Voter   map[string]string `json:"voter"`
}

func initTrillianMap() (*grpc.ClientConn, *trillian.TrillianMapClient, *helpers.MapInfo, error) {
	// For production usage, disable WithInsecure()
	g, err := grpc.Dial(*trillianMap, grpc.WithInsecure())
	if err != nil {
		return nil, nil, nil, err
	}
	tmc := trillian.NewTrillianMapClient(g)
	info := helpers.NewMapInfo(tmc, *mapID, context.Background())
	return g, &tmc, info, nil
}

func initTrillianLog() (*grpc.ClientConn, *trillian.TrillianLogClient, *helpers.LogInfo, error) {
	// For production usage, disable WithInsecure()
	g, err := grpc.Dial(*trillianLog, grpc.WithInsecure())
	if err != nil {
		return nil, nil, nil, err
	}

	tc := trillian.NewTrillianLogClient(g)
	info := helpers.NewLogInfo(tc, *logID, context.Background())

	return g, &tc, info, nil
}

func initTrillianMapLog() (*grpc.ClientConn, *trillian.TrillianLogClient, *helpers.LogInfo, error) {
	// For production usage, disable WithInsecure()
	g, err := grpc.Dial(*trillianLog, grpc.WithInsecure())
	if err != nil {
		return nil, nil, nil, err
	}

	tc := trillian.NewTrillianLogClient(g)
	info := helpers.NewLogInfo(tc, *mapLogID, context.Background())

	return g, &tc, info, nil
}

func sendHTTPResponse(w http.ResponseWriter, startTime time.Time, resp []byte) {
	if *testMode {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Response-Time", fmt.Sprintf("%d", int64(time.Since(startTime)/time.Millisecond)))
	}
	w.Write(resp)
}

func writeMapHeadToLog() error {
	gMap, tmc, mapInfo, err := initTrillianMap()
	if err != nil {
		log.Fatalf("Failed to init Trillian Map: %v", err)
	}
	defer gMap.Close()

	signedMapRootResp, err := (*tmc).GetSignedMapRoot(mapInfo.Ctx, &trillian.GetSignedMapRootRequest{
		MapId: mapInfo.MapID,
	})
	if err != nil {
		log.Printf("Failed to get signed map root: %v", err)
		return err
	}

	gLog, _, logInfo, err := initTrillianMapLog()
	if err != nil {
		log.Printf("Failed to init map log")
		return err
	}
	defer gLog.Close()

	err = logInfo.SaveRecord(signedMapRootResp.MapRoot, gLog)
	if err != nil {
		log.Printf("Error saving map log record")
		return err
	}

	return nil
}

func computeHmacString(key string, data string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func computeHmacByte(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func encryptVoter(voter map[string]string, r_id string, revision int64) map[string]string {
	// TODO: consider storing as byte array rather than JSON for space reasons
	encryptedVoter := make(map[string]string)
	for _, field := range fields {
		paddedLength := 0
		if strings.Contains(field, ":") {
			split := strings.Split(field, ":")
			if len(split) < 2 {
				log.Printf("Length not specified for %s", field)
				return nil
			}
			field = split[0]
			padded, err := strconv.Atoi(split[1])
			if err != nil {
				log.Printf("Could not parse length for %s", field)
				return nil
			}
			paddedLength = padded
		}
		// Unique key per field, per voter. As encKey is a randomly-generated 128 bit key, hmac is suitable as a KDF.
		// The key for each field should be returned to the voter.
		key := computeHmacByte([]byte(*encKey), fmt.Sprintf("%s|%s|%d", r_id, field, revision))
		encryptKey := computeHmacByte(key, "encrypt")
		hashKey := computeHmacByte(key, "hash")
		val := voter[field]
		if paddedLength > len(val) {
			// Pad the field
			val = fmt.Sprintf("%-*s\n", paddedLength, val)
		}

		block, err := aes.NewCipher(encryptKey)
		if err != nil {
			log.Printf("%v", err.Error())
			return nil
		}

		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			log.Printf("%v", err.Error())
			return nil
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			log.Printf("%v", err.Error())
			return nil
		}

		ciphertext := aesgcm.Seal(nil, nonce, []byte(val), nil)
		hmac := computeHmacByte(hashKey, string(ciphertext))
		encryptedVoter[field] = fmt.Sprintf("%s|%s|%s", base64.StdEncoding.EncodeToString(ciphertext), base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(hmac))
	}
	// status is not encrypted
	encryptedVoter["status"] = voter["status"]
	return encryptedVoter
}

func parseAndUpdateMetadata(existingVoter *string, r_id string, historyItem HistoryItem) (metadata string, error string) {
	var meta Metadata
	if existingVoter != nil {
		var existingVoterJSON map[string]string
		err := json.Unmarshal([]byte(*existingVoter), &existingVoterJSON)
		if err != nil {
			return "", "Malformed record"
		}

		err = json.Unmarshal([]byte(existingVoterJSON["metadata"]), &meta)
		if err != nil {
			return "", "Malformed record"
		}

		meta.Version = meta.Version + 1
		meta.History = append(meta.History, historyItem)
	} else {
		meta = Metadata{
			Version: 0,
			History: []HistoryItem{},
		}
		meta.History = append(meta.History, HistoryItem{
			Date:      time.Now(),
			EventType: "register",
			Signature: "",
			Signer:    "",
		})
	}
	jsonData, err := json.Marshal(meta)
	if err != nil {
		return "", "Error marshalling metadata"
	}
	return string(jsonData)[:], ""
}

func batchVoter(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	var request BatchVoterRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(body, &request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := request.Voter["status"]; !ok {
		http.Error(w, "status is required", http.StatusUnprocessableEntity)
		return
	}

	gLog, _, logInfo, err := initTrillianLog()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer gLog.Close()

	gMap, _, mapInfo, err := initTrillianMap()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer gMap.Close()

	revision, err := helpers.GetRevision(mapInfo, gMap)
	if err != nil {
		http.Error(w, "Error returning version", http.StatusInternalServerError)
		return
	}

	var voters []map[string]string
	for i := request.StartId; i < request.EndId; i++ {
		request.Voter["id"] = fmt.Sprintf("%d", i)

		r_id := computeHmacString(*idKey, request.Voter["id"])

		hashed := encryptVoter(request.Voter, r_id, revision)
		meta, error := parseAndUpdateMetadata(nil, r_id, HistoryItem{
			Date:      time.Now(),
			EventType: "update",
			Signature: "",
			Signer:    "",
		})
		if error != "" {
			http.Error(w, "Error: "+error, http.StatusInternalServerError)
			return
		}
		hashed["metadata"] = meta
		hashed["public_id"] = r_id
		voters = append(voters, hashed)
	}

	err = logInfo.SaveRecordBulk(voters, gLog)
	if err != nil {
		http.Error(w, "Error saving record", http.StatusInternalServerError)
		return
	}

	err = mapInfo.SaveRecordBulk(voters, gMap)
	if err != nil {
		http.Error(w, "Error saving record", http.StatusInternalServerError)
		return
	}

	err = writeMapHeadToLog()
	if err != nil {
		http.Error(w, "Error writing map head to log", http.StatusInternalServerError)
		return
	}

	jsonData, _ := json.Marshal(map[string]interface{}{
		"id": voters[0]["public_id"],
	})
	sendHTTPResponse(w, startTime, jsonData)
}

func addVoter(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	var voter map[string]string
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(body, &voter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, ok := voter["id"]; !ok {
		http.Error(w, "id is required", http.StatusUnprocessableEntity)
		return
	}

	if _, ok := voter["status"]; !ok {
		http.Error(w, "status is required", http.StatusUnprocessableEntity)
		return
	}

	gLog, _, logInfo, err := initTrillianLog()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer gLog.Close()

	gMap, tmc, mapInfo, err := initTrillianMap()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer gMap.Close()

	revision, err := helpers.GetRevision(mapInfo, gMap)
	if err != nil {
		http.Error(w, "Error returning version", http.StatusInternalServerError)
		return
	}

	r_id := computeHmacString(*idKey, voter["id"])
	hashed := encryptVoter(voter, r_id, revision)
	existingVoter := helpers.GetValue(tmc, *mapID, helpers.Hash(r_id))
	meta, error := parseAndUpdateMetadata(existingVoter, r_id, HistoryItem{
		Date:      time.Now(),
		EventType: "update",
		Signature: "",
		Signer:    "",
	})
	if error != "" {
		http.Error(w, "Error: "+error, http.StatusInternalServerError)
		return
	}
	hashed["metadata"] = meta
	hashed["public_id"] = r_id

	err = logInfo.SaveRecord(hashed, gLog)
	if err != nil {
		http.Error(w, "Error saving record", http.StatusInternalServerError)
		return
	}

	err = mapInfo.SaveRecord(r_id, hashed, gMap)
	if err != nil {
		http.Error(w, "Error saving record", http.StatusInternalServerError)
		return
	}

	jsonData, err := json.Marshal(map[string]interface{}{
		"id":   r_id,
		"data": hashed,
	})
	if err != nil {
		http.Error(w, "Error returning record", http.StatusInternalServerError)
		return
	}

	err = writeMapHeadToLog()
	if err != nil {
		http.Error(w, "Error writing map head to log", http.StatusInternalServerError)
		return
	}

	sendHTTPResponse(w, startTime, jsonData)
}

func getVoter(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	id := r.URL.Query().Get("id")

	_, tmc, _, err := initTrillianMap()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := helpers.GetValue(tmc, *mapID, helpers.Hash(id))
	if resp == nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	} else {
		sendHTTPResponse(w, startTime, []byte(*resp))
	}
}

func makeVoterInactive(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	id := r.URL.Query().Get("id")

	gLog, _, logInfo, err := initTrillianLog()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer gLog.Close()

	gMap, tmc, mapInfo, err := initTrillianMap()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer gMap.Close()

	voter := helpers.GetValue(tmc, *mapID, helpers.Hash(id))
	if voter == nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}
	meta, error := parseAndUpdateMetadata(voter, id, HistoryItem{
		Date:      time.Now(),
		EventType: "cancel",
		Signature: "",
		Signer:    "",
	})
	if error != "" {
		http.Error(w, "Error: "+error, http.StatusInternalServerError)
		return
	}
	var voterParsed map[string]string
	err = json.Unmarshal([]byte(*voter), &voterParsed)
	if err != nil {
		http.Error(w, "Record not found", http.StatusNotFound)
	}
	voterParsed["metadata"] = meta
	voterParsed["status"] = "cancelled"
	voterParsed["public_id"] = id

	err = logInfo.SaveRecord(voterParsed, gLog)
	if err != nil {
		http.Error(w, "Error saving record", http.StatusInternalServerError)
		return
	}

	err = mapInfo.SaveRecord(id, voterParsed, gMap)
	if err != nil {
		http.Error(w, "Error saving record", http.StatusInternalServerError)
		return
	}

	jsonData, err := json.Marshal(map[string]interface{}{
		"id":   id,
		"data": voterParsed,
	})
	if err != nil {
		http.Error(w, "Error returning record", http.StatusInternalServerError)
		return
	}

	err = writeMapHeadToLog()
	if err != nil {
		http.Error(w, "Error writing map head to log", http.StatusInternalServerError)
		return
	}

	sendHTTPResponse(w, startTime, jsonData)
}

func proveMembership(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	id := r.URL.Query().Get("id")

	_, tmc, _, err := initTrillianMap()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := helpers.GetInclusionProof(tmc, *mapID, helpers.Hash(id))
	if resp == nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	} else {
		jsonData, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, "Error returning record", http.StatusInternalServerError)
			return
		}
		sendHTTPResponse(w, startTime, jsonData)
	}
}

func verifyMembership(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	// Verify inclusion proof from proveMembership

	g, _, mapInfo, err := initTrillianMap()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var inclusionProof trillian.GetMapLeavesResponse
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(body, &inclusionProof)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	root, err := mapInfo.VerifyMapAppendOnlyProof(g, inclusionProof.MapRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = mapverifier.VerifyInclusionProof(*mapID, inclusionProof.MapLeafInclusion[0].Leaf, root.RootHash, inclusionProof.MapLeafInclusion[0].Inclusion, maphasher.Default)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		jsonData, err := json.Marshal(map[string]interface{}{
			"status": "success",
		})
		if err != nil {
			http.Error(w, "Error returning record", http.StatusInternalServerError)
			return
		}
		sendHTTPResponse(w, startTime, jsonData)
	}
}

func proveAppendOnly(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	gMap, _, mapInfo, err := initTrillianMap()
	if err != nil {
		log.Fatalf("Failed to init Trillian Map: %v", err)
	}
	defer gMap.Close()

	_, tc, _, err := initTrillianMapLog()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, tc2, _, err := initTrillianLog()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// convert to int
	first_tree_size, err := strconv.Atoi(r.URL.Query().Get("first_tree_size"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	mapAppendOnlyProof, err := mapInfo.GetMapAppendOnlyProof()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	mapLogProof := helpers.GetAppendOnlyProof(tc, *mapLogID, int64(first_tree_size))
	if mapLogProof == nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logProof := helpers.GetAppendOnlyProof(tc2, *logID, int64(first_tree_size))
	if logProof == nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := AppendOnlyProof{
		MapProof:    *mapAppendOnlyProof,
		LogProof:    *logProof,
		MapLogProof: *mapLogProof,
		Version:     int64(first_tree_size),
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Error returning record", http.StatusInternalServerError)
		return
	}
	sendHTTPResponse(w, startTime, jsonData)
}

/*
1. Verify that map log is append only.
2. Verify map is append only.
3. Verify log is append only.
4. Verify latest entry in map log matches root of map.
5. Verify latest version of all voters in log map version in map -- note: as this only verifies if the
map is append only, if a voter's record was change this would not detect it. Instead, the voter's records based on the log should be verified.
*/
func verifyAppendOnly(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	_, tmc, mapInfo, err := initTrillianMap()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	g, tc, _, err := initTrillianMapLog()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, tc2, _, err := initTrillianLog()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pubKey, err := helpers.GetKey(g, *mapLogID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pubKey2, err := helpers.GetKey(g, *logID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var appendOnlyProof AppendOnlyProof
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = json.Unmarshal(body, &appendOnlyProof)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify map log is append only
	_, err = helpers.VerifyAppendOnlyProof(tc, pubKey, appendOnlyProof.MapLogProof.SignedLogRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify map is append only
	_, err = mapInfo.VerifyMapAppendOnlyProof(g, appendOnlyProof.MapProof.MapRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify log is append only
	_, err = helpers.VerifyAppendOnlyProof(tc2, pubKey2, appendOnlyProof.LogProof.SignedLogRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Verified log is append only, now check that latest entry in map log matches root of map
	mapLogLeaves, err := (*tc).GetLeavesByRange(context.Background(), &trillian.GetLeavesByRangeRequest{LogId: *mapLogID, StartIndex: appendOnlyProof.Version, Count: 999999999, ChargeTo: nil})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(mapLogLeaves.Leaves) == 0 {
		http.Error(w, "Empty map log", http.StatusInternalServerError)
		return
	}

	leaf := mapLogLeaves.Leaves[len(mapLogLeaves.Leaves)-1]
	var mapRoot *trillian.SignedMapRoot
	err = json.Unmarshal(leaf.LeafValue, &mapRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !bytes.Equal(mapRoot.MapRoot, appendOnlyProof.MapProof.MapRoot.MapRoot) {
		http.Error(w, fmt.Sprintf("Map log %s does not match map root %s", mapRoot.MapRoot, &appendOnlyProof.MapProof.MapRoot.MapRoot), http.StatusInternalServerError)
		return
	}

	revision, err := helpers.GetRevision(mapInfo, g)

	// TODO: Add consistent batching
	batchSize := int64(500)
	verifiedVoters := make(map[string]bool)

	for i := revision * 2500; i >= appendOnlyProof.Version*2500; i -= batchSize {
		log.Printf("Verifying i= %d", i)
		// Verified log is append only, now check each record starting at bodyJSON.version to ensure it is valid
		logLeaves, err := (*tc2).GetLeavesByRange(context.Background(), &trillian.GetLeavesByRangeRequest{LogId: *logID, StartIndex: i, Count: batchSize, ChargeTo: nil})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		for j := range logLeaves.Leaves {
			// Iterate leaves backwards
			leaf := logLeaves.Leaves[len(logLeaves.Leaves)-1-j]
			var voter map[string]string
			err = json.Unmarshal(leaf.LeafValue, &voter)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Only verify the current record is valid
			if _, hasVerified := verifiedVoters[voter["public_id"]]; hasVerified {
				continue
			}

			// Get voter's record in the map
			record := helpers.GetValue(tmc, *mapID, helpers.Hash(voter["public_id"]))

			if *record != string(leaf.LeafValue) {
				http.Error(w, fmt.Sprintf("Map record %v does not match log value %v", *record, string(leaf.LeafValue)), http.StatusInternalServerError)
				return
			}
			verifiedVoters[voter["public_id"]] = true
		}
	}

	jsonData, err := json.Marshal(map[string]interface{}{
		"status": "success",
	})
	if err != nil {
		http.Error(w, "Error returning record", http.StatusInternalServerError)
		return
	}
	sendHTTPResponse(w, startTime, jsonData)
}

// Returns all records from map
func getVoters(w http.ResponseWriter, r *http.Request) {
	var err error

	s := r.URL.Query().Get("page_size")
	size := 100
	if s != "" {
		size, err = strconv.Atoi(s)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	i := r.URL.Query().Get("page_index")
	start := 0
	if i != "" {
		start, err = strconv.Atoi(i)
		if err != nil || start < 1 {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Start at 1
		start = (start - 1) * size
	}

	// io.WriteString(w, "{")
	// for n := start; n < start+size; n++ {
	// 	resp := records.GetValue(tmc, *mapID, records.KeyHash(n))
	// 	if resp == nil {
	// 		break
	// 	}
	// 	resp = records.GetValue(tmc, *mapID, records.RecordHash(*resp))
	// 	// FIXME: not formatted exactly like GDS registers...
	// 	//fmt.Fprintf(w, "%s\n", *resp)
	// 	r, k := fixRecord(*resp)
	// 	if n != start {
	// 		io.WriteString(w, ",")
	// 	}
	// 	fmt.Fprintf(w, "\"%s\":%s", k, r)
	// }
	// io.WriteString(w, "}")
}

func getVersion(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	gMap, _, mapInfo, _ := initTrillianMap()
	revision, err := helpers.GetRevision(mapInfo, gMap)
	if err != nil {
		http.Error(w, "Error returning version", http.StatusInternalServerError)
		return
	}
	jsonData, err := json.Marshal(map[string]interface{}{
		"version": revision,
	})
	if err != nil {
		http.Error(w, "Error returning version", http.StatusInternalServerError)
		return
	}
	sendHTTPResponse(w, startTime, jsonData)
}

func voter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		getVoter(w, r)
	case "POST":
		addVoter(w, r)
	case "DELETE":
		makeVoterInactive(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	flag.Parse()
	http.HandleFunc("/version", getVersion)
	http.HandleFunc("/voter", voter)
	http.HandleFunc("/voters", getVoters)
	http.HandleFunc("/voter/prove", proveMembership)
	http.HandleFunc("/voter/verify", verifyMembership)
	http.HandleFunc("/proveAppendOnly", proveAppendOnly)
	http.HandleFunc("/verifyAppendOnly", verifyAppendOnly)
	if *testMode {
		http.HandleFunc("/batchVoter", batchVoter)
	}
	log.Printf("Server listening on port 8084")
	log.Fatal(http.ListenAndServe("0.0.0.0:8084", nil))
}
