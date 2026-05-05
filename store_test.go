package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"sync"
	"testing"
)

func TestPathTransformFunc(t *testing.T) {
	key := "momsbestpicture"
	pathKey := CASPathTransformFunc(key)
	expectedFilename := "6804429f74181a63c50c3d81d733a12f14a353ff"
	expectedPathName := "68044/29f74/181a6/3c50c/3d81d/733a1/2f14a/353ff"
	if pathKey.PathName != expectedPathName {
		t.Errorf("have %s want %s", pathKey.PathName, expectedPathName)
	}

	if pathKey.Filename != expectedFilename {
		t.Errorf("have %s want %s", pathKey.Filename, expectedFilename)
	}
}

func TestStore(t *testing.T) {
	s := newStore()
	id := generateID()
	defer teardown(t, s)

	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("foo_%d", i)
		data := []byte("some jpg bytes")

		if _, err := s.writeStream(id, key, bytes.NewReader(data)); err != nil {
			t.Error(err)
		}

		if ok := s.Has(id, key); !ok {
			t.Errorf("expected to have key %s", key)
		}

		_, r, err := s.Read(id, key)
		if err != nil {
			t.Error(err)
		}

		b, _ := ioutil.ReadAll(r)
		if string(b) != string(data) {
			t.Errorf("want %s have %s", data, b)
		}

		if err := s.Delete(id, key); err != nil {
			t.Error(err)
		}

		if ok := s.Has(id, key); ok {
			t.Errorf("expected to NOT have key %s", key)
		}
	}
}

func TestStoreDedupe(t *testing.T) {
	s := newStore()
	id := generateID()
	defer teardown(t, s)

	key := "dedupe_me"
	data := []byte("identical bytes")

	if _, err := s.Write(id, key, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if got := s.DedupeHits(); got != 0 {
		t.Errorf("first write should not dedupe, got hits=%d", got)
	}

	// Second write with same key + content: must short-circuit and bump counter.
	if _, err := s.Write(id, key, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if got := s.DedupeHits(); got != 1 {
		t.Errorf("second write should dedupe, got hits=%d", got)
	}
}

func TestStoreEncryptedAtRest(t *testing.T) {
	s := newStore()
	id := generateID()
	defer teardown(t, s)

	key := "secret"
	plaintext := []byte("plaintext that must not appear on disk")
	encKey := newEncryptionKey()

	if _, err := s.WriteEncrypt(encKey, id, key, bytes.NewReader(plaintext)); err != nil {
		t.Fatal(err)
	}

	// Disk bytes are ciphertext, so a plaintext substring search must miss.
	_, raw, err := s.Read(id, key)
	if err != nil {
		t.Fatal(err)
	}
	rawBytes, _ := ioutil.ReadAll(raw)
	if bytes.Contains(rawBytes, plaintext) {
		t.Fatalf("plaintext leaked to disk: %q", rawBytes)
	}

	// ReadDecrypt must round-trip cleanly.
	_, dec, err := s.ReadDecrypt(encKey, id, key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := ioutil.ReadAll(dec)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypt mismatch: want %q got %q", plaintext, got)
	}
}

func TestStoreConcurrentWritesDistinctKeys(t *testing.T) {
	s := newStore()
	id := generateID()
	defer teardown(t, s)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("k_%d", i)
			if _, err := s.Write(id, key, bytes.NewReader([]byte(key))); err != nil {
				t.Errorf("write %s: %v", key, err)
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < 32; i++ {
		key := fmt.Sprintf("k_%d", i)
		if !s.Has(id, key) {
			t.Errorf("missing key %s after concurrent writes", key)
		}
	}
}

func newStore() *Store {
	opts := StoreOpts{
		PathTransformFunc: CASPathTransformFunc,
	}
	return NewStore(opts)
}

func teardown(t *testing.T, s *Store) {
	if err := s.Clear(); err != nil {
		t.Error(err)
	}
}

func TestStoreDeleteAfterDedupe(t *testing.T) {
	// Regression cover: dedupe-skipped writes must still be deletable.
	s := newStore()
	id := generateID()
	defer teardown(t, s)

	key := "k"
	data := []byte("payload")
	if _, err := s.Write(id, key, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(id, key, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(id, key); err != nil {
		t.Fatal(err)
	}
	if s.Has(id, key) {
		t.Error("file still present after delete")
	}
}
