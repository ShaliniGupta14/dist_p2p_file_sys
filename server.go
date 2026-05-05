package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/anthdm/foreverstore/p2p"
)

type FileServerOpts struct {
	ID                string
	EncKey            []byte
	StorageRoot       string
	PathTransformFunc PathTransformFunc
	Transport         p2p.Transport
	BootstrapNodes    []string
}

type FileServer struct {
	FileServerOpts

	peerLock sync.Mutex
	peers    map[string]p2p.Peer

	store  *Store
	quitch chan struct{}
}

func NewFileServer(opts FileServerOpts) *FileServer {
	storeOpts := StoreOpts{
		Root:              opts.StorageRoot,
		PathTransformFunc: opts.PathTransformFunc,
	}

	if len(opts.ID) == 0 {
		opts.ID = generateID()
	}

	return &FileServer{
		FileServerOpts: opts,
		store:          NewStore(storeOpts),
		quitch:         make(chan struct{}),
		peers:          make(map[string]p2p.Peer),
	}
}

// writeFrame serializes msg as gob, prepends [type byte][4-byte BE length],
// and writes the resulting frame to peer in a single send to keep it atomic
// with respect to the peer's read loop.
func writeFrame(peer p2p.Peer, msg *Message) error {
	body := new(bytes.Buffer)
	if err := gob.NewEncoder(body).Encode(msg); err != nil {
		return err
	}
	frame := new(bytes.Buffer)
	frame.WriteByte(p2p.IncomingMessage)
	if err := binary.Write(frame, binary.BigEndian, uint32(body.Len())); err != nil {
		return err
	}
	frame.Write(body.Bytes())
	return peer.Send(frame.Bytes())
}

func (s *FileServer) broadcast(msg *Message) error {
	s.peerLock.Lock()
	defer s.peerLock.Unlock()
	for _, peer := range s.peers {
		if err := writeFrame(peer, msg); err != nil {
			return err
		}
	}
	return nil
}

type Message struct {
	Payload any
}

type MessageStoreFile struct {
	ID  string
	Key string
}

type MessageGetFile struct {
	ID  string
	Key string
}

// fileChecksumLen is the byte length of the SHA-1 prefix that precedes
// every ciphertext file payload sent over the wire. Receivers re-hash the
// trailing bytes and compare; mismatch means rejected + not stored.
const fileChecksumLen = sha1.Size

// sendFileStream sends [IncomingStream][WriteStream of (sha1 || ciphertext)]
// to peer, computing the SHA-1 over ciphertext for end-to-end verification.
func sendFileStream(peer p2p.Peer, ciphertext []byte) error {
	if err := peer.Send([]byte{p2p.IncomingStream}); err != nil {
		return err
	}
	sum := sha1.Sum(ciphertext)
	body := io.MultiReader(bytes.NewReader(sum[:]), bytes.NewReader(ciphertext))
	total := int64(fileChecksumLen + len(ciphertext))
	_, err := p2p.WriteStream(peer, total, body)
	return err
}

// recvFileStream is the inverse of sendFileStream. It reads + reassembles the
// stream from peer, splits off the SHA-1 prefix, and verifies it matches.
// Returns the ciphertext on success.
func recvFileStream(peer p2p.Peer) ([]byte, error) {
	buf := new(bytes.Buffer)
	total, err := p2p.ReadStream(peer, buf)
	if err != nil {
		return nil, err
	}
	if total < fileChecksumLen {
		return nil, fmt.Errorf("stream too short: %d bytes", total)
	}
	data := buf.Bytes()
	want := data[:fileChecksumLen]
	ciphertext := data[fileChecksumLen:]
	got := sha1.Sum(ciphertext)
	if !bytes.Equal(got[:], want) {
		return nil, fmt.Errorf("checksum mismatch: want %x got %x", want, got)
	}
	return ciphertext, nil
}

func (s *FileServer) Get(key string) (io.Reader, error) {
	if s.store.Has(s.ID, key) {
		fmt.Printf("[%s] serving file (%s) from local disk\n", s.Transport.Addr(), key)
		_, r, err := s.store.ReadDecrypt(s.EncKey, s.ID, key)
		return r, err
	}

	fmt.Printf("[%s] dont have file (%s) locally, fetching from network...\n", s.Transport.Addr(), key)

	hashed := hashKey(key)
	msg := Message{
		Payload: MessageGetFile{
			ID:  s.ID,
			Key: hashed,
		},
	}
	if err := s.broadcast(&msg); err != nil {
		return nil, err
	}

	time.Sleep(time.Millisecond * 500)

	s.peerLock.Lock()
	peers := make([]p2p.Peer, 0, len(s.peers))
	for _, peer := range s.peers {
		peers = append(peers, peer)
	}
	s.peerLock.Unlock()

	for _, peer := range peers {
		ciphertext, err := recvFileStream(peer)
		peer.CloseStream()
		if err != nil {
			fmt.Printf("[%s] stream from %s failed: %s\n", s.Transport.Addr(), peer.RemoteAddr(), err)
			continue
		}
		if _, werr := s.store.Write(s.ID, hashed, bytes.NewReader(ciphertext)); werr != nil {
			return nil, werr
		}
		fmt.Printf("[%s] received (%d) bytes over the network from (%s)\n", s.Transport.Addr(), len(ciphertext), peer.RemoteAddr())
	}

	_, r, err := s.store.ReadDecrypt(s.EncKey, s.ID, hashed)
	return r, err
}

func (s *FileServer) Store(key string, r io.Reader) error {
	encrypted := new(bytes.Buffer)
	n, err := copyEncrypt(s.EncKey, r, encrypted)
	if err != nil {
		return err
	}
	ciphertext := encrypted.Bytes()
	hashed := hashKey(key)

	if _, err := s.store.Write(s.ID, hashed, bytes.NewReader(ciphertext)); err != nil {
		return err
	}

	msg := Message{
		Payload: MessageStoreFile{
			ID:  s.ID,
			Key: hashed,
		},
	}
	if err := s.broadcast(&msg); err != nil {
		return err
	}

	time.Sleep(time.Millisecond * 5)

	s.peerLock.Lock()
	peers := make([]p2p.Peer, 0, len(s.peers))
	for _, peer := range s.peers {
		peers = append(peers, peer)
	}
	s.peerLock.Unlock()

	for _, peer := range peers {
		if err := sendFileStream(peer, ciphertext); err != nil {
			return err
		}
	}

	fmt.Printf("[%s] stored and replicated (%d) ciphertext bytes\n", s.Transport.Addr(), n)
	return nil
}

func (s *FileServer) Stop() {
	close(s.quitch)
}

// Delete removes the local copy of a file. Network replicas are unaffected.
func (s *FileServer) Delete(key string) error {
	return s.store.Delete(s.ID, hashKey(key))
}

func (s *FileServer) OnPeer(p p2p.Peer) error {
	s.peerLock.Lock()
	defer s.peerLock.Unlock()

	s.peers[p.RemoteAddr().String()] = p

	log.Printf("connected with remote %s", p.RemoteAddr())

	return nil
}

func (s *FileServer) loop() {
	defer func() {
		log.Println("file server stopped due to error or user quit action")
		s.Transport.Close()
	}()

	for {
		select {
		case rpc := <-s.Transport.Consume():
			var msg Message
			if err := gob.NewDecoder(bytes.NewReader(rpc.Payload)).Decode(&msg); err != nil {
				log.Println("decoding error: ", err)
				continue
			}
			if err := s.handleMessage(rpc.From, &msg); err != nil {
				log.Println("handle message error: ", err)
			}

		case <-s.quitch:
			return
		}
	}
}

func (s *FileServer) handleMessage(from string, msg *Message) error {
	switch v := msg.Payload.(type) {
	case MessageStoreFile:
		return s.handleMessageStoreFile(from, v)
	case MessageGetFile:
		return s.handleMessageGetFile(from, v)
	}

	return nil
}

func (s *FileServer) handleMessageGetFile(from string, msg MessageGetFile) error {
	if !s.store.Has(msg.ID, msg.Key) {
		return fmt.Errorf("[%s] need to serve file (%s) but it does not exist on disk", s.Transport.Addr(), msg.Key)
	}

	fmt.Printf("[%s] serving file (%s) over the network\n", s.Transport.Addr(), msg.Key)

	_, rc, err := s.store.Read(msg.ID, msg.Key)
	if err != nil {
		return err
	}
	if closer, ok := rc.(io.Closer); ok {
		defer closer.Close()
	}
	ciphertext, err := io.ReadAll(rc)
	if err != nil {
		return err
	}

	s.peerLock.Lock()
	peer, ok := s.peers[from]
	s.peerLock.Unlock()
	if !ok {
		return fmt.Errorf("peer %s not in map", from)
	}

	if err := sendFileStream(peer, ciphertext); err != nil {
		return err
	}
	fmt.Printf("[%s] sent (%d) ciphertext bytes to %s\n", s.Transport.Addr(), len(ciphertext), from)
	return nil
}

func (s *FileServer) handleMessageStoreFile(from string, msg MessageStoreFile) error {
	s.peerLock.Lock()
	peer, ok := s.peers[from]
	s.peerLock.Unlock()
	if !ok {
		return fmt.Errorf("peer (%s) could not be found in the peer list", from)
	}

	ciphertext, err := recvFileStream(peer)
	peer.CloseStream()
	if err != nil {
		return fmt.Errorf("recv file stream from %s: %w", from, err)
	}

	n, err := s.store.Write(msg.ID, msg.Key, bytes.NewReader(ciphertext))
	if err != nil {
		return err
	}

	fmt.Printf("[%s] written %d ciphertext bytes to disk\n", s.Transport.Addr(), n)
	return nil
}

func (s *FileServer) bootstrapNetwork() error {
	for _, addr := range s.BootstrapNodes {
		if len(addr) == 0 {
			continue
		}

		go func(addr string) {
			fmt.Printf("[%s] attemping to connect with remote %s\n", s.Transport.Addr(), addr)
			if err := s.Transport.Dial(addr); err != nil {
				log.Println("dial error: ", err)
			}
		}(addr)
	}

	return nil
}

func (s *FileServer) Start() error {
	fmt.Printf("[%s] starting fileserver...\n", s.Transport.Addr())

	if err := s.Transport.ListenAndAccept(); err != nil {
		return err
	}

	s.bootstrapNetwork()

	s.loop()

	return nil
}

func init() {
	gob.Register(MessageStoreFile{})
	gob.Register(MessageGetFile{})
}
