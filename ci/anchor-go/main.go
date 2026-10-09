// Command anchor-go checks conformance/anchor-v1-vectors.json with reference
// implementations instead of 4GARTHA's own Python code (ASSURANCE.md section 7):
//
//   - sigsum.org/sigsum-go v0.14.1: RFC 6962 hashing and inclusion proofs
//     (pkg/merkle), checkpoints (pkg/checkpoint), trust policies (pkg/policy)
//     and Sigsum proofs (pkg/proof), plus its sigsum-verify command
//   - golang.org/x/mod v0.35.0 sumdb/note: the canonical signed-note code
//
// For every vector it requires the reference outcome recorded in the vectors
// (sigsum_go, x_mod_note, sigsum_verify) and the expected hashes. Where a
// recorded reference outcome differs from 4GARTHA's own expected outcome, the
// vectors document a deliberate strictness difference; this program checks
// that the reference behaves as recorded, so a drift on either side fails.
//
// It fails closed: a missing section, a vector count below the expected
// minimum, a vector it did not evaluate, or any mismatch exits non-zero.
//
// With -anchors DIR it also checks a stored anchor log (ledger/anchors) the
// same way: leaves.json parsed and the tree rebuilt with sigsum-go, every
// checkpoint's root compared, and, given -policy, every checkpoint signature
// (x/mod note) and Sigsum proof (sigsum-go and sigsum-verify) verified. Stored
// proofs without a policy fail: there is nothing to verify them against.
//
// Usage: anchor-go -vectors FILE [-sigsum-verify PATH] [-anchors DIR [-policy FILE]]
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"sigsum.org/sigsum-go/pkg/checkpoint"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
)

type vectors struct {
	Protocol string `json:"protocol"`
	RFC6962  *struct {
		Leaves []string `json:"leaves"`
		Roots  []string `json:"roots"`
	} `json:"rfc6962"`
	SignedNoteExample *struct {
		Vkey string `json:"vkey"`
		Note string `json:"note"`
	} `json:"signed_note_example"`
	AnchorTree *struct {
		Records    []string `json:"records"`
		LeafHashes []string `json:"leaf_hashes"`
		Roots      []string `json:"roots"`
		Inclusion  []struct {
			Index uint64   `json:"index"`
			Size  uint64   `json:"size"`
			Path  []string `json:"path"`
		} `json:"inclusion"`
	} `json:"anchor_tree"`
	Checkpoints []struct {
		Name      string `json:"name"`
		Note      string `json:"note"`
		Origin    string `json:"origin"`
		PublicKey string `json:"public_key"`
		SigsumGo  string `json:"sigsum_go"`
		XModNote  string `json:"x_mod_note"`
	} `json:"checkpoints"`
	Policies []struct {
		Name     string `json:"name"`
		Text     string `json:"text"`
		SigsumGo string `json:"sigsum_go"`
	} `json:"policies"`
	SigsumProofs []struct {
		Name            string `json:"name"`
		CheckpointText  string `json:"checkpoint_text"`
		AnchorPublicKey string `json:"anchor_public_key"`
		Policy          string `json:"policy"`
		Proof           string `json:"proof"`
		SigsumVerify    string `json:"sigsum_verify"`
	} `json:"sigsum_proofs"`
	AnchorLog *struct {
		Policy  string                       `json:"policy"`
		Batches map[string]map[string]string `json:"batches"`
		Times   map[string]uint64            `json:"anchored_no_later_than"`
	} `json:"anchor_log"`
}

var (
	failures int
	checked  = map[string]int{}
)

func fail(section, name, format string, args ...any) {
	failures++
	fmt.Printf("FAIL %s/%s: %s\n", section, name, fmt.Sprintf(format, args...))
}

func ok(section string) { checked[section]++ }

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("vectors contain invalid hex %q: %v", s, err))
	}
	return b
}

func hash32(s string) crypto.Hash {
	var h crypto.Hash
	b := mustHex(s)
	if len(b) != len(h) {
		panic(fmt.Sprintf("expected 32 bytes of hex, got %d", len(b)))
	}
	copy(h[:], b)
	return h
}

func pubkey(s string) crypto.PublicKey {
	var k crypto.PublicKey
	copy(k[:], mustHex(s))
	return k
}

func outcome(err error) string {
	if err == nil {
		return "accept"
	}
	return "reject"
}

// sigsumPolicyText drops the 4GARTHA-only anchor-origin/anchor-key lines; the
// rest of a 4gartha.anchor-policy/1 file is Sigsum policy syntax.
func sigsumPolicyText(text string) string {
	var out []string
	for _, line := range strings.SplitAfter(text, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasPrefix(f[0], "anchor-") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "")
}

func treeOf(leafHashes []crypto.Hash) merkle.Tree {
	t := merkle.NewTree()
	for i := range leafHashes {
		if !t.AddLeafHash(&leafHashes[i]) {
			panic("duplicate leaf hash in vectors")
		}
	}
	return t
}

func checkRFC6962(v *vectors) {
	const s = "rfc6962"
	if v.RFC6962 == nil || len(v.RFC6962.Leaves) != 8 || len(v.RFC6962.Roots) != 9 {
		fail(s, "-", "section missing or not 8 leaves / 9 roots")
		return
	}
	var lh []crypto.Hash
	for _, l := range v.RFC6962.Leaves {
		lh = append(lh, merkle.HashLeafNode(mustHex(l)))
	}
	if got := merkle.HashEmptyTree(); hex.EncodeToString(got[:]) != v.RFC6962.Roots[0] {
		fail(s, "size-0", "empty root %x", got)
	} else {
		ok(s)
	}
	for n := 1; n <= 8; n++ {
		t := treeOf(lh[:n])
		if got := t.GetRootHash(); hex.EncodeToString(got[:]) != v.RFC6962.Roots[n] {
			fail(s, fmt.Sprintf("size-%d", n), "root %x, vectors say %s", got, v.RFC6962.Roots[n])
		} else {
			ok(s)
		}
	}
}

func checkSignedNoteExample(v *vectors) {
	const s = "signed_note_example"
	if v.SignedNoteExample == nil {
		fail(s, "-", "section missing")
		return
	}
	verifier, err := note.NewVerifier(v.SignedNoteExample.Vkey)
	if err != nil {
		fail(s, "vkey", "%v", err)
		return
	}
	if _, err := note.Open([]byte(v.SignedNoteExample.Note), note.VerifierList(verifier)); err != nil {
		fail(s, "note", "x/mod note.Open: %v", err)
		return
	}
	var nv checkpoint.NoteVerifier
	if err := nv.FromString(v.SignedNoteExample.Vkey); err != nil {
		fail(s, "vkey", "sigsum-go NoteVerifier: %v", err)
		return
	}
	if checkpoint.NewKeyId(nv.Name, nv.Type, &nv.PublicKey) != nv.KeyId {
		fail(s, "key-id", "sigsum-go key ID does not match the vkey")
		return
	}
	ok(s)
}

func checkAnchorTree(v *vectors) {
	const s = "anchor_tree"
	at := v.AnchorTree
	if at == nil || len(at.Records) < 7 || len(at.Records) != len(at.LeafHashes) || len(at.Roots) != len(at.Records)+1 {
		fail(s, "-", "section missing or inconsistent")
		return
	}
	var lh []crypto.Hash
	for i, rid := range at.Records {
		raw := mustHex(rid)
		if len(raw) != 32 || strings.ToLower(rid) != rid {
			fail(s, rid, "record ID is not 64 lowercase hex")
			continue
		}
		h := merkle.HashLeafNode(raw) // the leaf is the record ID's 32 raw bytes
		if hex.EncodeToString(h[:]) != at.LeafHashes[i] {
			fail(s, rid, "leaf hash %x, vectors say %s", h, at.LeafHashes[i])
		}
		lh = append(lh, h)
	}
	for n := 0; n <= len(lh); n++ {
		var got crypto.Hash
		if n == 0 {
			got = merkle.HashEmptyTree()
		} else {
			t := treeOf(lh[:n])
			got = t.GetRootHash()
		}
		if hex.EncodeToString(got[:]) != at.Roots[n] {
			fail(s, fmt.Sprintf("root-%d", n), "root %x, vectors say %s", got, at.Roots[n])
		} else {
			ok(s)
		}
	}
	full := treeOf(lh)
	want := 0
	for n := 1; n <= len(lh); n++ {
		want += n
	}
	if len(at.Inclusion) != want {
		fail(s, "inclusion", "%d inclusion vectors, expected every (index, size): %d", len(at.Inclusion), want)
	}
	for _, inc := range at.Inclusion {
		name := fmt.Sprintf("inclusion-%d-of-%d", inc.Index, inc.Size)
		ref, err := full.ProveInclusion(inc.Index, inc.Size)
		if err != nil {
			fail(s, name, "sigsum-go ProveInclusion: %v", err)
			continue
		}
		var path []crypto.Hash
		for _, p := range inc.Path {
			path = append(path, hash32(p))
		}
		if fmt.Sprintf("%x", ref) != fmt.Sprintf("%x", path) {
			fail(s, name, "path differs from sigsum-go's")
			continue
		}
		root := hash32(at.Roots[inc.Size])
		if err := merkle.VerifyInclusion(&lh[inc.Index], inc.Index, inc.Size, &root, path); err != nil {
			fail(s, name, "sigsum-go VerifyInclusion: %v", err)
			continue
		}
		ok(s)
	}
}

func checkCheckpoints(v *vectors) {
	const s = "checkpoints"
	for _, c := range v.Checkpoints {
		pk := pubkey(c.PublicKey)
		// checkpoint.Checkpoint.Verify only knows Sigsum's own origin
		// (sigsum.org/v1/tree/<key hash>), so verify a custom-origin
		// checkpoint from sigsum-go's parser and primitives instead.
		var cp checkpoint.Checkpoint
		err := cp.FromASCII(bytes.NewBufferString(c.Note))
		if err == nil && cp.Origin != c.Origin {
			err = fmt.Errorf("origin %q is not %q", cp.Origin, c.Origin)
		}
		if err == nil && cp.KeyId != checkpoint.NewLogKeyId(c.Origin, &pk) {
			err = fmt.Errorf("signature line key ID is not this key's")
		}
		if err == nil && !crypto.Verify(&pk, []byte(cp.TreeHead.FormatCheckpoint(cp.Origin)), &cp.Signature) {
			err = fmt.Errorf("invalid checkpoint signature")
		}
		if got := outcome(err); got != c.SigsumGo {
			fail(s, c.Name, "sigsum-go checkpoint: %s (%v), vectors record %s", got, err, c.SigsumGo)
			continue
		}
		vkey := fmt.Sprintf("%s+%08x+%s", c.Origin,
			checkpoint.NewLogKeyId(c.Origin, &pk),
			base64.StdEncoding.EncodeToString(append([]byte{byte(checkpoint.SigTypeEd25519)}, pk[:]...)))
		verifier, verr := note.NewVerifier(vkey)
		if verr != nil {
			fail(s, c.Name, "x/mod NewVerifier(%q): %v", vkey, verr)
			continue
		}
		_, err = note.Open([]byte(c.Note), note.VerifierList(verifier))
		if got := outcome(err); got != c.XModNote {
			fail(s, c.Name, "x/mod note.Open: %s (%v), vectors record %s", got, err, c.XModNote)
			continue
		}
		ok(s)
	}
}

func checkPolicies(v *vectors) {
	const s = "policies"
	for _, p := range v.Policies {
		_, err := policy.ParseConfig(bytes.NewBufferString(sigsumPolicyText(p.Text)))
		if got := outcome(err); got != p.SigsumGo {
			fail(s, p.Name, "sigsum-go ParseConfig: %s (%v), vectors record %s", got, err, p.SigsumGo)
			continue
		}
		ok(s)
	}
}

func opensshPublicKey(pk crypto.PublicKey) string {
	var blob bytes.Buffer
	for _, part := range [][]byte{[]byte("ssh-ed25519"), pk[:]} {
		binary.Write(&blob, binary.BigEndian, uint32(len(part)))
		blob.Write(part)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " 4gartha-test-anchor\n"
}

func checkProofs(v *vectors, sigsumVerify, work string) {
	const s = "sigsum_proofs"
	const sv = "sigsum_verify_command"
	for i, p := range v.SigsumProofs {
		msg := crypto.Hash(sha256.Sum256([]byte(p.CheckpointText)))
		anchor := pubkey(p.AnchorPublicKey)
		pol, err := policy.ParseConfig(bytes.NewBufferString(sigsumPolicyText(p.Policy)))
		if err != nil {
			fail(s, p.Name, "policy does not parse with sigsum-go: %v", err)
			continue
		}
		var pr proof.SigsumProof
		err = pr.FromASCII(bytes.NewBufferString(p.Proof))
		if err == nil {
			err = pr.Verify(&msg, map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(anchor[:]): anchor}, pol)
		}
		if got := outcome(err); got != p.SigsumVerify {
			fail(s, p.Name, "sigsum-go proof.Verify: %s (%v), vectors record %s", got, err, p.SigsumVerify)
		} else {
			ok(s)
		}
		if sigsumVerify == "" {
			continue
		}
		dir := filepath.Join(work, fmt.Sprintf("%03d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			panic(err)
		}
		files := map[string]string{"anchor.pub": opensshPublicKey(anchor), "policy": sigsumPolicyText(p.Policy), "proof": p.Proof}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				panic(err)
			}
		}
		cmd := exec.Command(sigsumVerify, "--raw-hash", "-k", filepath.Join(dir, "anchor.pub"),
			"-p", filepath.Join(dir, "policy"), filepath.Join(dir, "proof"))
		cmd.Stdin = strings.NewReader(hex.EncodeToString(msg[:]) + "\n")
		out, err := cmd.CombinedOutput()
		if _, isExit := err.(*exec.ExitError); err != nil && !isExit {
			fail(sv, p.Name, "could not run %s: %v", sigsumVerify, err)
			continue
		}
		if got := outcome(err); got != p.SigsumVerify {
			fail(sv, p.Name, "sigsum-verify: %s (%s), vectors record %s", got, strings.TrimSpace(string(out)), p.SigsumVerify)
			continue
		}
		ok(sv)
	}
}

// anchorPolicy extracts the 4GARTHA-only lines of a 4gartha.anchor-policy/1 file.
func anchorPolicy(text string) (origin string, key crypto.PublicKey, err error) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 2 && f[0] == "anchor-origin":
			origin = f[1]
		case len(f) == 2 && f[0] == "anchor-key":
			key, err = crypto.PublicKeyFromHex(f[1])
			if err != nil {
				return "", key, err
			}
		}
	}
	if origin == "" {
		return "", key, fmt.Errorf("policy has no anchor-origin line")
	}
	return origin, key, nil
}

type leavesDoc struct {
	PreviousSize *uint64  `json:"previous_size"`
	Protocol     string   `json:"protocol"`
	Records      []string `json:"records"`
}

var batchName = regexp.MustCompile(`^[0-9]{12}$`)

// checkAnchorLog rebuilds an anchor log stored as directory batches. It
// returns the number of batches checked and per-batch time bounds are not
// computed here (the policy quorum check is sigsum-go's own).
func checkAnchorLog(section, dir, policyText, sigsumVerify, work string) int {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		fail(section, dir, "%v", err)
		return 0
	}
	var names []string
	for _, e := range entries {
		if e.Name() == ".keep" {
			continue
		}
		if !e.IsDir() || !batchName.MatchString(e.Name()) {
			fail(section, e.Name(), "unexpected entry")
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var (
		origin   string
		key      crypto.PublicKey
		pol      *policy.Policy
		verifier note.Verifier
	)
	if policyText != "" {
		if origin, key, err = anchorPolicy(policyText); err != nil {
			fail(section, "policy", "%v", err)
			return 0
		}
		if pol, err = policy.ParseConfig(bytes.NewBufferString(sigsumPolicyText(policyText))); err != nil {
			fail(section, "policy", "sigsum-go ParseConfig: %v", err)
			return 0
		}
		vkey := fmt.Sprintf("%s+%08x+%s", origin, checkpoint.NewLogKeyId(origin, &key),
			base64.StdEncoding.EncodeToString(append([]byte{byte(checkpoint.SigTypeEd25519)}, key[:]...)))
		if verifier, err = note.NewVerifier(vkey); err != nil {
			fail(section, "policy", "x/mod NewVerifier: %v", err)
			return 0
		}
	}
	tree := merkle.NewTree()
	var size uint64
	checkedBatches := 0
	for _, name := range names {
		bdir := filepath.Join(dir, name)
		read := func(f string) ([]byte, bool) {
			b, err := os.ReadFile(filepath.Join(bdir, f))
			if os.IsNotExist(err) {
				return nil, false
			}
			if err != nil {
				fail(section, name, "%s: %v", f, err)
				return nil, false
			}
			return b, true
		}
		leavesData, ok1 := read("leaves.json")
		noteData, ok2 := read("checkpoint")
		if !ok1 || !ok2 {
			fail(section, name, "missing leaves.json or checkpoint")
			continue
		}
		var doc leavesDoc
		dec := json.NewDecoder(bytes.NewReader(leavesData))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil || doc.PreviousSize == nil || doc.Protocol != "4gartha.anchor/1" || len(doc.Records) == 0 {
			fail(section, name, "leaves.json is not a 4gartha.anchor/1 batch (%v)", err)
			continue
		}
		if *doc.PreviousSize != size {
			fail(section, name, "previous_size %d, but the log before it ends at %d", *doc.PreviousSize, size)
			continue
		}
		for _, rid := range doc.Records {
			raw, err := hex.DecodeString(rid)
			if err != nil || len(raw) != 32 || strings.ToLower(rid) != rid {
				fail(section, name, "record %q is not 64 lowercase hex", rid)
				continue
			}
			h := merkle.HashLeafNode(raw)
			if !tree.AddLeafHash(&h) {
				fail(section, name, "record %s is already in the log", rid)
			}
		}
		size = tree.Size()
		if name != fmt.Sprintf("%012d", size) {
			fail(section, name, "directory name does not match tree size %d", size)
			continue
		}
		var cp checkpoint.Checkpoint
		if err := cp.FromASCII(bytes.NewReader(noteData)); err != nil {
			fail(section, name, "sigsum-go checkpoint: %v", err)
			continue
		}
		root := tree.GetRootHash()
		if cp.Size != size || cp.RootHash != root {
			fail(section, name, "checkpoint (size %d, root %x) does not match the rebuilt tree (size %d, root %x)", cp.Size, cp.RootHash, size, root)
			continue
		}
		proofData, hasProof := read("sigsum.proof")
		if pol == nil {
			if hasProof {
				fail(section, name, "stored Sigsum proof, but no -policy to verify it against")
				continue
			}
			checkedBatches++
			continue
		}
		n, err := note.Open(noteData, note.VerifierList(verifier))
		if err != nil || cp.Origin != origin {
			fail(section, name, "checkpoint is not signed by the policy's anchor key for origin %q (%v)", origin, err)
			continue
		}
		if hasProof {
			msg := crypto.Hash(sha256.Sum256([]byte(n.Text)))
			var pr proof.SigsumProof
			err := pr.FromASCII(bytes.NewReader(proofData))
			if err == nil {
				err = pr.Verify(&msg, map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(key[:]): key}, pol)
			}
			if err != nil {
				fail(section, name, "sigsum-go proof.Verify: %v", err)
				continue
			}
			if sigsumVerify != "" {
				pdir := filepath.Join(work, section+"-"+name)
				os.MkdirAll(pdir, 0o755)
				os.WriteFile(filepath.Join(pdir, "anchor.pub"), []byte(opensshPublicKey(key)), 0o644)
				os.WriteFile(filepath.Join(pdir, "policy"), []byte(sigsumPolicyText(policyText)), 0o644)
				os.WriteFile(filepath.Join(pdir, "proof"), proofData, 0o644)
				cmd := exec.Command(sigsumVerify, "--raw-hash", "-k", filepath.Join(pdir, "anchor.pub"),
					"-p", filepath.Join(pdir, "policy"), filepath.Join(pdir, "proof"))
				cmd.Stdin = strings.NewReader(hex.EncodeToString(msg[:]) + "\n")
				if out, err := cmd.CombinedOutput(); err != nil {
					fail(section, name, "sigsum-verify: %v: %s", err, strings.TrimSpace(string(out)))
					continue
				}
			}
		}
		checkedBatches++
	}
	return checkedBatches
}

func checkAnchorLogVector(v *vectors, sigsumVerify, work string) {
	const s = "anchor_log"
	al := v.AnchorLog
	if al == nil || len(al.Batches) < 2 {
		fail(s, "-", "section missing or fewer than 2 batches")
		return
	}
	dir := filepath.Join(work, "anchor-log-vector")
	for name, files := range al.Batches {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			panic(err)
		}
		for f, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name, f), []byte(content), 0o644); err != nil {
				panic(err)
			}
		}
	}
	before := failures
	n := checkAnchorLog(s, dir, al.Policy, sigsumVerify, work)
	if n != len(al.Batches) && failures == before {
		fail(s, "-", "checked %d of %d batches", n, len(al.Batches))
	}
	checked[s] += n
}

func main() {
	vectorsPath := flag.String("vectors", "", "conformance/anchor-v1-vectors.json")
	sigsumVerify := flag.String("sigsum-verify", "", "path to the sigsum-verify binary (optional)")
	anchorsDir := flag.String("anchors", "", "also check a stored anchor log, e.g. ledger/anchors (optional)")
	policyFile := flag.String("policy", "", "4gartha.anchor-policy/1 file for the stored anchor log (optional)")
	flag.Parse()
	if *vectorsPath == "" {
		fmt.Fprintln(os.Stderr, "usage: anchor-go -vectors FILE [-sigsum-verify PATH]")
		os.Exit(2)
	}
	data, err := os.ReadFile(*vectorsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var v vectors
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&v); err != nil {
		fmt.Fprintln(os.Stderr, "invalid vectors:", err)
		os.Exit(2)
	}
	if v.Protocol != "4gartha.anchor/1" {
		fmt.Fprintf(os.Stderr, "unexpected protocol %q\n", v.Protocol)
		os.Exit(2)
	}
	work, err := os.MkdirTemp("", "anchor-go-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(work)

	checkRFC6962(&v)
	checkSignedNoteExample(&v)
	checkAnchorTree(&v)
	checkCheckpoints(&v)
	checkPolicies(&v)
	checkProofs(&v, *sigsumVerify, work)
	checkAnchorLogVector(&v, *sigsumVerify, work)
	if *anchorsDir != "" {
		policyText := ""
		if *policyFile != "" {
			b, err := os.ReadFile(*policyFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			policyText = string(b)
		}
		n := checkAnchorLog("stored_anchor_log", *anchorsDir, policyText, *sigsumVerify, work)
		fmt.Printf("ok   %-22s %d batch(es)\n", "stored_anchor_log", n)
	}

	// Never report success without having evaluated every vector, and at least
	// a minimum per section (a loop that silently ran zero times cannot pass).
	minimum := map[string]int{"rfc6962": 9, "signed_note_example": 1, "anchor_tree": 36,
		"checkpoints": 20, "policies": 23, "sigsum_proofs": 33, "anchor_log": 2}
	total := map[string]int{"checkpoints": len(v.Checkpoints), "policies": len(v.Policies), "sigsum_proofs": len(v.SigsumProofs)}
	if *sigsumVerify != "" {
		minimum["sigsum_verify_command"] = minimum["sigsum_proofs"]
		total["sigsum_verify_command"] = len(v.SigsumProofs)
	}
	for section, min := range minimum {
		if checked[section] < min {
			fail(section, "-", "only %d vector(s) checked, expected at least %d", checked[section], min)
		}
		if want, ok := total[section]; ok && checked[section] != want && failures == 0 {
			fail(section, "-", "checked %d of %d vectors", checked[section], want)
		}
	}
	for _, section := range []string{"rfc6962", "signed_note_example", "anchor_tree", "checkpoints", "policies", "sigsum_proofs", "sigsum_verify_command", "anchor_log"} {
		if n, present := checked[section]; present {
			fmt.Printf("ok   %-22s %d\n", section, n)
		}
	}
	if failures != 0 {
		fmt.Printf("anchor-go: %d failure(s)\n", failures)
		os.Exit(1)
	}
	fmt.Println("anchor-go: every vector matches the reference implementations")
}
