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

// HashResult represents the result of MD5-hashing an IPv4 address.
type HashResult struct {
	Hash string
	IP   net.IP
}

// incIP returns an IPv4 address one greater than the provided IPv4 address.
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

// HashIP returns a HashResult pointer with the IP and hex-encoded MD5 value.
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

// BruteIPNet bruteforces an IPv4 subnet and pushes results matching the hashes sought to the provided channel.
func BruteIPNet(ipnet *net.IPNet, hashes Hashes, channel chan<- *HashResult) {
	// iterate over the range of IPv4 addresses in the provided IPv4 subnet,
	for ip := ipnet.IP; ipnet.Contains(ip); ip = incIP(ip) {
		result := HashIP(ip) // hash the current IPv4 address

		// check if the hash exists in the table,
		if _, ok := hashes[result.Hash]; ok {
			// output the result,
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
		dsn string // data source name of the MySQL target

		src  string // source file path of the file target
		dest string // file path of the file destination
	)

	var hashes Hashes

	// define CLI args,
	fs := flag.NewFlagSetWithEnvPrefix(os.Args[0], "KX_IPMD5", 0)
	fs.StringVar(&dsn, "dsn", "", "data source name of the MySQL target")
	fs.StringVar(&src, "srcfile", "", "source file path of the file target")
	fs.StringVar(&dest, "destfile", "", "file path of the file destination")

	// parse CLI args,
	fs.Parse(os.Args[1:])

	// create the channels,
	channel := make(chan *HashResult) // results channel
	jobs := make(chan *net.IPNet)     // IPv4 subnet jobs channel

	if len(src) > 0 { // file-based
		// open the source file,
		fmt.Printf("reading hashes from file: %s\n", src)
		file, err := os.Open(src)

		if err != nil {
			panic(err)
		}

		// defer closing the source file to when the program is finished,
		defer func() {
			fmt.Printf("closing hashes from file: %s\n", src)
			file.Close()
		}()

		// read all of the hashes from the source file,
		hashes = FileHashesRead(file)
	} else { // unknown!
		panic(fmt.Errorf("no source method"))
	}

	// ascertain the destination method,
	if len(dest) > 0 { // file-based
		// open the destination file,
		fmt.Printf("writing results to file: %s\n", dest)
		file, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE, 0666)

		if err != nil {
			panic(err)
		}

		// defer closing the destination file to when the program is finished,
		defer func() {
			fmt.Printf("closing results to file: %s\n", dest)
			file.Close()
		}()

		// start a worker for writing the results to the destination file,
		go FileHashResultWrite(file, channel)
	} else { // unknown!
		panic(fmt.Errorf("no destination method"))
	}

	// count the CPUs
	numCPUs := runtime.NumCPU()

	// generate a number of workers for all but one processor,
	for w := 1; w <= numCPUs-1; w++ {
		go BruteIPNetWorker(w, hashes, jobs, channel)
	}

	// mask for top-level IPv4 subnets.
	mask := []byte{255, 0, 0, 0}

	// iterate over the range of top-level IPv4 subnets,
	for toplev := byte(254); toplev > 0; toplev-- {
		// create the IPv4 network representation of the current top-level
		ipnet := &net.IPNet{
			IP:   []byte{toplev, 0, 0, 0},
			Mask: mask,
		}

		// push the job for the current IPv4 subnet,
		fmt.Printf("add brute forcing job for %v.0.0.0/8\n", toplev)
		jobs <- ipnet
	}

	// once all top-level IPv4 subnets have been worked over,
	// all jobs are done, cleanup,
	fmt.Println("closing jobs: done")
	close(jobs)
}
