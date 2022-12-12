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
	return hashedVoter
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
	_, ok := voter["id"]
	if !ok {
		http.Error(w, "id is required", http.StatusUnprocessableEntity)
		return
	}

	// For production usage, disable WithInsecure()
	g, err := grpc.Dial(*trillianMap, grpc.WithInsecure())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmc := trillian.NewTrillianMapClient(g)
	info := helpers.NewInfo(tmc, *mapID, context.Background())

	r_id := computeHmac(*idKey, voter["id"])
	hashed := hashVoter(voter)

	revision := helpers.GetRevision(info, g) + 1

	info.SaveRecord(r_id, hashed, revision)

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

	// For production usage, disable WithInsecure()
	g, err := grpc.Dial(*trillianMap, grpc.WithInsecure())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmc := trillian.NewTrillianMapClient(g)

	resp := helpers.GetValue(tmc, *mapID, helpers.Hash(id))
	if resp == nil {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(*resp))
	}
}

func main() {
	flag.Parse()

	http.HandleFunc("/add_voter", addVoter)
	http.HandleFunc("/get_voter", getVoter)
	log.Fatal(http.ListenAndServe("localhost:8084", nil))
}
