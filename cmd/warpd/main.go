package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"cmit/paas/warp/pkg/config"
	"cmit/paas/warp/pkg/server"

	flags "github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	var opts struct {
		ConfigFile    string `short:"c" long:"config" description:"specify the configuration file path" default:"warpd.yaml"`
		LogLevel      string `short:"l" long:"log-level" description:"specifying log level"`
		DisableStdlog bool   `long:"disable-stdlog" description:"disable standard logging"`
		GrpcPort      int    `short:"p" long:"api-port" description:"specify the port that warp listen on" default:"8081"`
		PProfHost     string `long:"pprof-host" description:"specify the host that warpd listens on for pprof" default:"localhost:6060"`
		PProfDisable  bool   `long:"pprof-disable" description:"disable pprof profiling"`
	}

	_, err := flags.Parse(&opts)
	if err != nil {
		fmt.Println("Parse start params failed: ", err)
		os.Exit(1)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	/*
		if !opts.PProfDisable {
			go func() {
				log.Println(http.ListenAndServe(opts.PProfHost, nil))
			}()
		}
	*/

	initLog(opts.LogLevel, opts.DisableStdlog)

	conf, err := config.ReadConfig(opts.ConfigFile)
	if err != nil {
		log.Errorf("read configuration file failed: %v", err)
		os.Exit(1)
	}

	s, err := server.NewAPIServer(grpc.NewServer(), conf, uint16(opts.GrpcPort))
	if err != nil {
		log.Errorf("create warp server failed: %v", err)
		os.Exit(1)
	}
	if err = s.Serve(); err != nil {
		log.Errorf("warp serve failed: %v", err)
		os.Exit(1)
	}
	defer s.Stop()

	fmt.Print(`
__  _  _______ _____________  
\ \/ \/ /\__  \\_  __ \____ \ 
 \     /  / __ \|  | \/  |_> >
  \/\_/  (____  /__|  |   __/ 
              \/      |__|    
`)
	<-sigCh
}

func initLog(level string, disableStd bool) {
	switch level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	if disableStd {
		log.SetOutput(io.Discard)
	} else {
		log.SetOutput(os.Stdout)
	}
}
