package main
// Temporary file

import (
	"flag"
	"fmt"
	"os"
	"github.com/bearded-web/scripts/retirejs"
	"code.google.com/p/go.net/context"
	"github.com/bearded-web/bearded/pkg/script/mango"
	"github.com/bearded-web/bearded/models/scan")

var socketAddr *string = flag.String("sockAddr", "", "")

func run(addr string) {
	app := retirejs.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := mango.NewClient(addr)
	if err != nil {
		panic(err)
	}
	conf := scan.ScanConf{
		Target: "http://skimmer.tulu.la",
	}
	println("handle")
	app.Handle(ctx, client, conf)
}

func main() {
	flag.Parse()
	if socketAddr == nil || *socketAddr == "" {
		fmt.Printf("sockAddr param is required\n")
		os.Exit(1)
	}
	run(*socketAddr)

}
