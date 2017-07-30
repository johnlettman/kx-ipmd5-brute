package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/namsral/flag"
)

// Hashes represents a constant-time unique lookup table for checking whether a hash is in the pool of those to break.
type Hashes map[string]struct{}

type HashResult struct {
	Hash string
	IP   net.IP
}

func incIP(ip net.IP) net.IP {
	i := make(net.IP, 4)
	copy(i, ip)

	for j := len(i) - 1; j >= 0; j-- {
		i[j]++

		if i[j] > 0 {
			break
		}
	}

	return i
}

func HashIP(ip net.IP) *HashResult {
	hasher := md5.New()
	hasher.Write([]byte(ip.String()))

	i := make(net.IP, 4)
	copy(i, ip)

	return &HashResult{
		Hash: hex.EncodeToString(hasher.Sum(nil)),
		IP:   i,
	}
}

func BruteIPNet(ipnet *net.IPNet, hashes Hashes, channel chan<- *HashResult) {
	for ip := ipnet.IP; ipnet.Contains(ip); ip = incIP(ip) {
		result := HashIP(ip)

		if _, ok := hashes[result.Hash]; ok {
			fmt.Printf("match found! %s = %s\n", result.Hash, result.IP.String())
			channel <- result
		}
	}
}

func BruteCIDR(cidr string, hashes Hashes, channel chan<- *HashResult) error {
	_, ipnet, err := net.ParseCIDR(cidr)

	if err != nil {
		return err
	}

	BruteIPNet(ipnet, hashes, channel)
	return nil
}

func BruteIPNetWorker(id int, hashes Hashes, jobs <-chan *net.IPNet, channel chan<- *HashResult) {
	jid := 0

	for ipnet := range jobs {
		jid++
		fmt.Printf("worker #%v starting job #%v for IPNet %v\n", id, jid, ipnet)
		BruteIPNet(ipnet, hashes, channel)
		fmt.Printf("worker #%v finished job #%v for IPNet %v\n", id, jid, ipnet)
	}
}

func FileHashResultWrite(file *os.File, channel chan *HashResult) {
	for result := range channel {
		fmt.Printf("writing %s=%v\n", result.Hash, result.IP)
		fmt.Fprintf(file, "%s=%s\n", result.Hash, result.IP.String())
	}
}

func FileHashesRead(file *os.File) Hashes {
	hashes := make(Hashes)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		hash := scanner.Text()
		fmt.Printf("loading hash: %s\n", hash)
		hashes[hash] = struct{}{}
	}

	return hashes
}

func init() {
	numCPUs := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPUs + 1)
}

func main() {
	var (
		dsn string

		src  string
		dest string
	)

	var ipnet *net.IPNet
	var hashes Hashes

	fs := flag.NewFlagSetWithEnvPrefix(os.Args[0], "KX_IPMD5", 0)
	fs.StringVar(&dsn, "dsn", "", "data source name of the MySQL target")
	fs.StringVar(&src, "srcfile", "", "source file path of the file target")
	fs.StringVar(&dest, "destfile", "", "file path of the file destination")

	fs.Parse(os.Args[1:])
	channel := make(chan *HashResult)
	jobs := make(chan *net.IPNet)

	if len(src) > 0 {
		fmt.Printf("reading hashes from file: %s\n", src)
		file, err := os.Open(src)

		if err != nil {
			panic(err)
		}

		defer func() {
			fmt.Printf("closing hashes from file: %s\n", src)
			file.Close()
		}()

		hashes = FileHashesRead(file)
	} else {
		panic(fmt.Errorf("no source method"))
	}

	if len(dest) > 0 {
		fmt.Printf("writing results to file: %s\n", dest)
		file, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE, 0666)

		if err != nil {
			panic(err)
		}

		defer func() {
			fmt.Printf("closing results to file: %s\n", dest)
			file.Close()
		}()

		go FileHashResultWrite(file, channel)
	} else {
		panic(fmt.Errorf("no destination method"))
	}

	numCPUs := runtime.NumCPU()

	for w := 1; w <= numCPUs-1; w++ {
		go BruteIPNetWorker(w, hashes, jobs, channel)
	}

	toplev := byte(254)
	toplevMask := []byte{255, 0, 0, 0}

	for ; toplev > 0; toplev-- {
		ipnet = &net.IPNet{
			IP:   []byte{toplev, 0, 0, 0},
			Mask: toplevMask,
		}

		fmt.Printf("add brute forcing job for %v.0.0.0/8\n", toplev)
		jobs <- ipnet
	}

	fmt.Println("closing jobs: done")
	close(jobs)
}
