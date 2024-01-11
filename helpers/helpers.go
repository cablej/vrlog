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
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto"

	// "github.com/google/trillian/merkle/logverifier"

	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type LogInfo struct {
	LogID int64
	Tc    trillian.TrillianLogClient
	Ctx   context.Context
}

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

func GetRevision(info *MapInfo, g *grpc.ClientConn) (int64, error) {
	signedMapRootResp, err := info.Tc.GetSignedMapRoot(info.Ctx, &trillian.GetSignedMapRootRequest{
		MapId: info.MapID,
	})
	if err != nil {
		log.Printf("Failed to get signed map root: %v", err)
		return 0, err
	}

	pubKey, err := GetKey(g, info.MapID)
	if err != nil {
		log.Printf("Failed to get key: %v", err)
		return 0, err
	}
	mrv1, err := crypto.VerifySignedMapRoot(pubKey, gocrypto.SHA256, signedMapRootResp.MapRoot)
	if err != nil {
		log.Printf("Failed to verify signed root: %v", err)
		return 0, err
	}

	return int64(mrv1.Revision), nil
}

func GetInclusionProof(tmc *trillian.TrillianMapClient, id int64, hash []byte) *trillian.GetMapLeavesResponse {
	index := [1][]byte{hash}
	req := &trillian.GetMapLeavesRequest{
		MapId: id,
		Index: index[:],
	}

	resp, err := (*tmc).GetLeaves(context.Background(), req)
	if err != nil {
		log.Printf("Can't get leaf '%s': %v", hex.EncodeToString(hash), err)
		return nil
	}
	return resp
}

func GetAppendOnlyProof(tc *trillian.TrillianLogClient, id int64, treeSize int64) *trillian.GetLatestSignedLogRootResponse {
	req := &trillian.GetLatestSignedLogRootRequest{
		LogId:         id,
		FirstTreeSize: treeSize,
		ChargeTo:      nil,
	}

	resp, err := (*tc).GetLatestSignedLogRoot(context.Background(), req)
	if err != nil {
		log.Printf("Can't get latest signed root '%d': %v", treeSize, err)
		return nil
	}
	return resp
}

func VerifyAppendOnlyProof(tc *trillian.TrillianLogClient, pubKey gocrypto.PublicKey, signed_log_root *trillian.SignedLogRoot) (*types.LogRootV1, error) {
	verifier := client.NewLogVerifier(rfc6962.DefaultHasher, pubKey, gocrypto.SHA256)
	root, err := crypto.VerifySignedLogRoot(verifier.PubKey, verifier.SigHash, signed_log_root)
	if err == nil {
		// Signature verified and unmarshalled correctly. The struct may now
		// be used.
		// if root.TreeSize > 0 {
		// 	// Non empty tree.
		// }
		return root, nil
	}
	return nil, err
}

func GetValue(tmc *trillian.TrillianMapClient, id int64, hash []byte) *string {
	index := [1][]byte{hash}
	req := &trillian.GetMapLeavesRequest{
		MapId: id,
		Index: index[:],
	}

	resp, err := (*tmc).GetLeaves(context.Background(), req)
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
func (i *MapInfo) addToMap(h []byte, v []byte, revision int64) error {
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
		log.Printf("SetLeaves() failed: %v", err)
		return err
	}
	return nil
}

// Converts record to JSON and hashes it before adding to map
func (i *MapInfo) SaveRecord(key string, value interface{}, g *grpc.ClientConn) error {
	revision, err := GetRevision(i, g)
	if err != nil {
		return err
	}
	revision = revision + 1

	v, err := json.Marshal(value)
	if err != nil {
		log.Printf("Marshal() failed: %v", err)
		return err
	}

	hash := Hash(key)
	if err := i.addToMap(hash, v, revision); err != nil {
		return err
	}
	return nil
}

// Converts record to JSON and hashes it before adding to map
func (i *LogInfo) SaveRecord(value interface{}, g *grpc.ClientConn) error {
	v, err := json.Marshal(value)
	if err != nil {
		log.Printf("Marshal() failed: %v", err)
		return err
	}

	// Send to Trillian
	tl := &trillian.LogLeaf{LeafValue: v}
	q := &trillian.QueueLeafRequest{LogId: i.LogID, Leaf: tl}
	r, err := i.Tc.QueueLeaf(i.Ctx, q)
	if err != nil {
		return err
	}

	// And check everything worked
	c := codes.Code(r.QueuedLeaf.GetStatus().GetCode())
	if c != codes.OK && c != codes.AlreadyExists {
		return fmt.Errorf("bad return status: %v", r.QueuedLeaf.GetStatus())
	}

	return nil
}

// Helper function to convert fields into logInfo struct
func NewLogInfo(tc trillian.TrillianLogClient, logID int64, ctx context.Context) *LogInfo {
	i := &LogInfo{LogID: logID, Tc: tc, Ctx: ctx}
	return i
}

// Helper function to convert fields into mapInfo struct
func NewMapInfo(tc trillian.TrillianMapClient, mapID int64, ctx context.Context) *MapInfo {
	// FIXME: need to figure out current keyCount...
	i := &MapInfo{MapID: mapID, Tc: tc, Ctx: ctx}
	return i
}
