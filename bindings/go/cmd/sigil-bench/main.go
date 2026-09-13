package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sigiltiktoken/tiktoken"
)

type result struct {
	Language         string `json:"language"`
	Vocab            string `json:"vocab"`
	Corpus           string `json:"corpus"`
	Rounds           int    `json:"rounds"`
	Items            int    `json:"items"`
	TotalTokens      int    `json:"total_tokens"`
	EncodeNsPerToken int64  `json:"encode_ns_per_token"`
	DecodeNsPerToken int64  `json:"decode_ns_per_token"`
	RoundtripParity  bool   `json:"roundtrip_parity"`
	Specials         bool   `json:"specials"`
}

func loadCorpus(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var corpus []string
	if err := json.Unmarshal(data, &corpus); err != nil {
		return nil, err
	}
	return corpus, nil
}

func main() {
	defaultCorpus := filepath.Clean(filepath.Join("..", "..", "bench", "corpora", "stress.json"))
	corpusPath := flag.String("corpus", defaultCorpus, "JSON corpus of strings")
	vocab := flag.String("vocab", "cl100k_base", "Tokenizer vocab")
	rounds := flag.Int("rounds", 20, "Number of benchmark rounds")
	jsonOut := flag.Bool("json", false, "Emit JSON")
	flag.Parse()

	corpus, err := loadCorpus(*corpusPath)
	if err != nil {
		panic(err)
	}
	if len(corpus) == 0 {
		panic("corpus is empty")
	}

	tokenizer, err := tiktoken.Open(*vocab)
	if err != nil {
		panic(err)
	}
	defer tokenizer.Close()

	encodeDurations := make([]int64, 0, *rounds)
	decodeDurations := make([]int64, 0, *rounds)
	totalTokens := 0
	parity := true

	for i := 0; i < *rounds; i++ {
		start := time.Now()
		encoded := make([][]uint32, 0, len(corpus))
		for _, text := range corpus {
			ids, err := tokenizer.Encode(text)
			if err != nil {
				panic(err)
			}
			encoded = append(encoded, ids)
		}
		encodeDurations = append(encodeDurations, time.Since(start).Nanoseconds())

		start = time.Now()
		for idx, ids := range encoded {
			decoded, err := tokenizer.Decode(ids)
			if err != nil {
				panic(err)
			}
			if decoded != corpus[idx] {
				parity = false
			}
		}
		decodeDurations = append(decodeDurations, time.Since(start).Nanoseconds())

		for _, ids := range encoded {
			totalTokens += len(ids)
		}
	}

	mean := func(values []int64) int64 {
		var sum int64
		for _, value := range values {
			sum += value
		}
		if totalTokens == 0 {
			return 0
		}
		return sum / int64(totalTokens)
	}

	out := result{
		Language:         "go",
		Vocab:            *vocab,
		Corpus:           *corpusPath,
		Rounds:           *rounds,
		Items:            len(corpus),
		TotalTokens:      totalTokens,
		EncodeNsPerToken: mean(encodeDurations),
		DecodeNsPerToken: mean(decodeDurations),
		RoundtripParity:  parity,
		Specials:         false,
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			panic(err)
		}
		return
	}

	fmt.Printf(
		"go binding benchmark\n  vocab: %s\n  corpus: %s\n  rounds: %d\n  items: %d\n  total tokens: %d\n  encode ns/token: %d\n  decode ns/token: %d\n  roundtrip parity: %t\n",
		out.Vocab,
		out.Corpus,
		out.Rounds,
		out.Items,
		out.TotalTokens,
		out.EncodeNsPerToken,
		out.DecodeNsPerToken,
		out.RoundtripParity,
	)
}
