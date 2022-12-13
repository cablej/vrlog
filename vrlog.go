package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cablej/vrlog/helpers"
	"github.com/google/trillian"
	"google.golang.org/grpc"
)

var (
	trillianMap = flag.String("trillian_map", "localhost:8093", "address of the Trillian Map RPC server.")
	mapID       = flag.Int64("map_id", 0, "Trillian MapID to write.")
	idKey       = flag.String("id_key", "secret1", "Key to use to generate ids.")
	saltKey     = flag.String("salt_key", "secret2", "Key used to generate salts.")
	fieldsStr   = flag.String("fields", "id,firstName,lastName,dob,ssn", "Comma-separated list of fields to include in the voter record.")
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

func initTrillian() (*grpc.ClientConn, *trillian.TrillianMapClient, *helpers.MapInfo, error) {
	// For production usage, disable WithInsecure()
	g, err := grpc.Dial(*trillianMap, grpc.WithInsecure())
	if err != nil {
		return nil, nil, nil, err
	}
	tmc := trillian.NewTrillianMapClient(g)
	info := helpers.NewInfo(tmc, *mapID, context.Background())
	return g, &tmc, info, nil
}

func computeHmac(key string, data string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func hashVoter(voter map[string]string) map[string]string {
	// TODO: consider storing as byte array rather than JSON for space reasons
	hashedVoter := make(map[string]string)
	for _, field := range fields {
		// Unique salt per field, per voter
		salt := computeHmac(*saltKey, fmt.Sprintf("%s|%s", voter["id"], field))
		val := voter[field]
		hashedVoter[field] = hex.EncodeToString(helpers.Hash(fmt.Sprintf("%s|%s", val, salt)))
	}
	// status is not hashed
	hashedVoter["status"] = voter["status"]
	return hashedVoter
}

func parseAndUpdateMetadata(existingVoter *string, tmc *trillian.TrillianMapClient, r_id string, historyItem HistoryItem) (metadata string, error string) {
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
		// TODO: allow importing existing records
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

func addVoter(w http.ResponseWriter, r *http.Request) {
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

	g, tmc, info, err := initTrillian()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	r_id := computeHmac(*idKey, voter["id"])
	hashed := hashVoter(voter)
	existingVoter := helpers.GetValue(tmc, *mapID, helpers.Hash(r_id))
	meta, error := parseAndUpdateMetadata(existingVoter, tmc, r_id, HistoryItem{
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

	err = info.SaveRecord(r_id, hashed, g)

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
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func getVoter(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	_, tmc, _, err := initTrillian()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := helpers.GetValue(tmc, *mapID, helpers.Hash(id))
	if resp == nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(*resp))
	}
}

func cancelVoter(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	g, tmc, info, err := initTrillian()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	voter := helpers.GetValue(tmc, *mapID, helpers.Hash(id))
	if voter == nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}
	meta, error := parseAndUpdateMetadata(voter, tmc, id, HistoryItem{
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

	err = info.SaveRecord(id, voterParsed, g)

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
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func proveMembership(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")

	_, tmc, _, err := initTrillian()
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
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonData)
	}
}

func voter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		getVoter(w, r)
	case "POST":
		addVoter(w, r)
	case "DELETE":
		cancelVoter(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func main() {
	flag.Parse()
	http.HandleFunc("/voter", voter)
	http.HandleFunc("/voter/prove", proveMembership)
	log.Fatal(http.ListenAndServe("localhost:8084", nil))
}
