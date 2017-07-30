package main

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/jlettman/kx-ipmd5-brute/brute"
	"github.com/namsral/flag"
)

func init() {
	numCPUs := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPUs + 1)
}

func main() {
	var (
		dsn string // data source name of the MySQL target

		src     string // source file path of the file target
		dest    string // file path of the file destination
		version bool   // output the version
	)

	var hashes brute.Hashes

	// define CLI args,
	fs := flag.NewFlagSetWithEnvPrefix(os.Args[0], "KX_IPMD5", 0)
	fs.StringVar(&dsn, "dsn", "", "data source name of the MySQL target")
	fs.StringVar(&src, "srcfile", "", "source file path of the file target")
	fs.StringVar(&dest, "destfile", "", "file path of the file destination")
	fs.BoolVar(&version, "version", false, "output the version")

	// parse CLI args,
	fs.Parse(os.Args[1:])

	if version {
		fmt.Printf("%s-%s\n", brute.Version, brute.Commit)
		return
	}

	// create the channels,
	channel := make(chan *brute.HashResult) // results channel
	jobs := make(chan *net.IPNet)           // IPv4 subnet jobs channel

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
		hashes = brute.FileHashesRead(file)
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
		go brute.FileHashResultWrite(file, channel)
	} else { // unknown!
		panic(fmt.Errorf("no destination method"))
	}

	// count the CPUs
	numCPUs := runtime.NumCPU()

	// generate a number of workers for all but one processor,
	for w := 1; w <= numCPUs-1; w++ {
		go brute.BruteIPNetWorker(w, hashes, jobs, channel)
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
