package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

const defaultRootFolderName = "ggnetwork"

func CASPathTransformFunc(key string) PathKey {
	hash := sha1.Sum([]byte(key))
	hashStr := hex.EncodeToString(hash[:])

	blocksize := 5
	sliceLen := len(hashStr) / blocksize
	paths := make([]string, sliceLen)

	for i := 0; i < sliceLen; i++ {
		from, to := i*blocksize, (i*blocksize)+blocksize
		paths[i] = hashStr[from:to]
	}

	return PathKey{
		PathName: strings.Join(paths, "/"),
		Filename: hashStr,
	}
}

type PathTransformFunc func(string) PathKey

type PathKey struct {
	PathName string
	Filename string
}

func (p PathKey) FirstPathName() string {
	paths := strings.Split(p.PathName, "/")
	if len(paths) == 0 {
		return ""
	}
	return paths[0]
}

func (p PathKey) FullPath() string {
	return fmt.Sprintf("%s/%s", p.PathName, p.Filename)
}

type StoreOpts struct {
	// Root is the folder name of the root, containing all the folders/files of the system.
	Root              string
	PathTransformFunc PathTransformFunc
}

var DefaultPathTransformFunc = func(key string) PathKey {
	return PathKey{
		PathName: key,
		Filename: key,
	}
}

type Store struct {
	StoreOpts

	// keyLocksMu guards keyLocks. Per-key RWMutex serializes concurrent
	// Write/Read/Delete on the same key while still allowing parallel access
	// across distinct keys.
	keyLocksMu sync.Mutex
	keyLocks   map[string]*sync.RWMutex

	// dedupeHits counts writes that were short-circuited because the
	// content-addressed file already existed on disk.
	dedupeHits int64
}

func NewStore(opts StoreOpts) *Store {
	if opts.PathTransformFunc == nil {
		opts.PathTransformFunc = DefaultPathTransformFunc
	}
	if len(opts.Root) == 0 {
		opts.Root = defaultRootFolderName
	}

	return &Store{
		StoreOpts: opts,
		keyLocks:  make(map[string]*sync.RWMutex),
	}
}

func (s *Store) lockFor(id, key string) *sync.RWMutex {
	full := id + "/" + key
	s.keyLocksMu.Lock()
	defer s.keyLocksMu.Unlock()
	l, ok := s.keyLocks[full]
	if !ok {
		l = &sync.RWMutex{}
		s.keyLocks[full] = l
	}
	return l
}

// DedupeHits returns the number of writes skipped because the CAS path already existed.
func (s *Store) DedupeHits() int64 {
	return atomic.LoadInt64(&s.dedupeHits)
}

func (s *Store) Has(id string, key string) bool {
	l := s.lockFor(id, key)
	l.RLock()
	defer l.RUnlock()
	return s.hasUnlocked(id, key)
}

func (s *Store) hasUnlocked(id, key string) bool {
	pathKey := s.PathTransformFunc(key)
	fullPathWithRoot := fmt.Sprintf("%s/%s/%s", s.Root, id, pathKey.FullPath())
	_, err := os.Stat(fullPathWithRoot)
	return !errors.Is(err, os.ErrNotExist)
}

func (s *Store) Clear() error {
	return os.RemoveAll(s.Root)
}

func (s *Store) Delete(id string, key string) error {
	l := s.lockFor(id, key)
	l.Lock()
	defer l.Unlock()

	pathKey := s.PathTransformFunc(key)

	defer func() {
		log.Printf("deleted [%s] from disk", pathKey.Filename)
	}()

	firstPathNameWithRoot := fmt.Sprintf("%s/%s/%s", s.Root, id, pathKey.FirstPathName())
	return os.RemoveAll(firstPathNameWithRoot)
}

// Write stores the byte stream as-is (caller is responsible for any encryption).
// If the CAS path already holds the file, the write is skipped, the reader is
// fully drained (so the wire stays aligned), and the existing size is returned.
func (s *Store) Write(id string, key string, r io.Reader) (int64, error) {
	l := s.lockFor(id, key)
	l.Lock()
	defer l.Unlock()
	return s.writeStreamUnlocked(id, key, r)
}

// WriteEncrypt encrypts the input with encKey (AES-256-CTR, IV-prefixed) and
// writes the resulting ciphertext to disk. This is the local-first persistence
// path and is what gives the system its "encrypted at rest" property.
func (s *Store) WriteEncrypt(encKey []byte, id, key string, r io.Reader) (int64, error) {
	l := s.lockFor(id, key)
	l.Lock()
	defer l.Unlock()

	pathKey := s.PathTransformFunc(key)
	fullPath := fmt.Sprintf("%s/%s/%s", s.Root, id, pathKey.FullPath())
	if fi, err := os.Stat(fullPath); err == nil {
		if _, derr := io.Copy(io.Discard, r); derr != nil {
			return 0, derr
		}
		atomic.AddInt64(&s.dedupeHits, 1)
		return fi.Size(), nil
	}

	f, err := s.openFileForWriting(id, key)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	n, err := copyEncrypt(encKey, r, f)
	return int64(n), err
}

// WriteDecrypt reads ciphertext from r, decrypts with encKey, writes plaintext to disk.
// Used when the network sends raw plaintext (legacy path) — kept for compatibility.
func (s *Store) WriteDecrypt(encKey []byte, id string, key string, r io.Reader) (int64, error) {
	l := s.lockFor(id, key)
	l.Lock()
	defer l.Unlock()

	f, err := s.openFileForWriting(id, key)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, err := copyDecrypt(encKey, r, f)
	return int64(n), err
}

func (s *Store) openFileForWriting(id string, key string) (*os.File, error) {
	pathKey := s.PathTransformFunc(key)
	pathNameWithRoot := fmt.Sprintf("%s/%s/%s", s.Root, id, pathKey.PathName)
	if err := os.MkdirAll(pathNameWithRoot, os.ModePerm); err != nil {
		return nil, err
	}

	fullPathWithRoot := fmt.Sprintf("%s/%s/%s", s.Root, id, pathKey.FullPath())
	return os.Create(fullPathWithRoot)
}

func (s *Store) writeStreamUnlocked(id, key string, r io.Reader) (int64, error) {
	pathKey := s.PathTransformFunc(key)
	fullPath := fmt.Sprintf("%s/%s/%s", s.Root, id, pathKey.FullPath())
	if fi, err := os.Stat(fullPath); err == nil {
		if _, derr := io.Copy(io.Discard, r); derr != nil {
			return 0, derr
		}
		atomic.AddInt64(&s.dedupeHits, 1)
		return fi.Size(), nil
	}

	f, err := s.openFileForWriting(id, key)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(f, r)
}

// writeStream is retained for tests that exercise the lower-level write path directly.
func (s *Store) writeStream(id, key string, r io.Reader) (int64, error) {
	return s.Write(id, key, r)
}

// Read returns the raw bytes stored on disk. With encrypted-at-rest writes,
// these will be ciphertext; callers should prefer ReadDecrypt.
func (s *Store) Read(id string, key string) (int64, io.Reader, error) {
	l := s.lockFor(id, key)
	l.RLock()
	defer l.RUnlock()
	return s.readStreamUnlocked(id, key)
}

// ReadDecrypt reads the (ciphertext) file from disk and decrypts it with encKey,
// returning the plaintext as a reader.
func (s *Store) ReadDecrypt(encKey []byte, id, key string) (int64, io.Reader, error) {
	l := s.lockFor(id, key)
	l.RLock()
	defer l.RUnlock()

	_, rc, err := s.readStreamUnlocked(id, key)
	if err != nil {
		return 0, nil, err
	}
	defer rc.Close()

	out := new(bytes.Buffer)
	n, err := copyDecrypt(encKey, rc, out)
	if err != nil {
		return 0, nil, err
	}
	// copyDecrypt's count includes the 16-byte IV; subtract for plaintext size.
	return int64(n - 16), out, nil
}

func (s *Store) readStreamUnlocked(id, key string) (int64, io.ReadCloser, error) {
	pathKey := s.PathTransformFunc(key)
	fullPathWithRoot := fmt.Sprintf("%s/%s/%s", s.Root, id, pathKey.FullPath())

	file, err := os.Open(fullPathWithRoot)
	if err != nil {
		return 0, nil, err
	}

	fi, err := file.Stat()
	if err != nil {
		return 0, nil, err
	}

	return fi.Size(), file, nil
}
