package helpers

// Key types
import (
	"context"
	gocrypto "crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto"
	"google.golang.org/grpc"
)

type MapInfo struct {
	MapID    int64
	Tc       trillian.TrillianMapClient
	Ctx      context.Context
	KeyCount int
}

func Hash(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

// Helper function to return the public key of a given map ID
func GetKey(conn *grpc.ClientConn, logID int64) (interface{}, error) {
	a := trillian.NewTrillianAdminClient(conn)
	log.Printf("Getting key for log %d", logID)
	log.Printf("%s", context.Background())
	tree, err := a.GetTree(context.Background(), &trillian.GetTreeRequest{TreeId: logID})
	if err != nil {
		return nil, fmt.Errorf("call to GetTree failed: %v", err)
	}

	if tree == nil {
		return nil, fmt.Errorf("log %d not found", logID)
	}

	publicKey := tree.GetPublicKey()
	return x509.ParsePKIXPublicKey(publicKey.GetDer())
}

func GetRevision(info *MapInfo, g *grpc.ClientConn) int64 {
	signedMapRootResp, err := info.Tc.GetSignedMapRoot(info.Ctx, &trillian.GetSignedMapRootRequest{
		MapId: info.MapID,
	})

	pubKey, err := GetKey(g, info.MapID)
	if err != nil {
		log.Fatalf("Failed to get key: %v", err)
	}
	mrv1, err := crypto.VerifySignedMapRoot(pubKey, gocrypto.SHA256, signedMapRootResp.MapRoot)
	if err != nil {
		log.Fatalf("Failed to verify signed root: %v", err)
	}

	return int64(mrv1.Revision)
}

func GetValue(tmc trillian.TrillianMapClient, id int64, hash []byte) *string {
	index := [1][]byte{hash}
	req := &trillian.GetMapLeavesRequest{
		MapId: id,
		Index: index[:],
	}

	resp, err := tmc.GetLeaves(context.Background(), req)
	if err != nil {
		log.Printf("Can't get leaf '%s': %v", hex.EncodeToString(hash), err)
		return nil
	}
	if resp.MapLeafInclusion[0].Leaf.LeafValue == nil {
		return nil
	}
	s := string(resp.MapLeafInclusion[0].Leaf.LeafValue)
	return &s
}

// Internal helper function to add record to map
func (i *MapInfo) addToMap(h []byte, v []byte, revision int64) {
	l := trillian.MapLeaf{
		Index:     h,
		LeafValue: v,
	}

	req := trillian.SetMapLeavesRequest{
		MapId:    i.MapID,
		Leaves:   []*trillian.MapLeaf{&l},
		Revision: revision,
	}

	if _, err := i.Tc.SetLeaves(i.Ctx, &req); err != nil {
		log.Fatalf("SetLeaves() failed: %v", err)
	}
}

// Converts record to JSON and hashes it before adding to map
func (i *MapInfo) SaveRecord(key string, value interface{}, revision int64) {
	fmt.Printf("evicting %v -> %v\n", key, value)

	v, err := json.Marshal(value)
	if err != nil {
		log.Fatalf("Marshal() failed: %v", err)
	}

	hash := Hash(key)
	i.addToMap(hash, v, revision)
}

// Helper function to convert fields into mapInfo struct
func NewInfo(tc trillian.TrillianMapClient, mapID int64, ctx context.Context) *MapInfo {
	// FIXME: need to figure out current keyCount...
	i := &MapInfo{MapID: mapID, Tc: tc, Ctx: ctx}
	return i
}
