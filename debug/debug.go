package debug

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"syscall"
	"time"
)

const (
	defaultProfileDir    = "./debug/profiles"
	timeFormat           = "20060102_150405"
	cpuProfileRate       = 10000
	blockProfileRate     = 1
	mutexProfileFraction = 1
)

type ProfileType string

const (
	ProfileCPU       ProfileType = "cpu"
	ProfileMemory    ProfileType = "mem"
	ProfileTrace     ProfileType = "trace"
	ProfileBlock     ProfileType = "block"
	ProfileMutex     ProfileType = "mutex"
	ProfileGoroutine ProfileType = "goroutine"
)

type Debug struct {
	enabled    bool
	profileDir string
	cpuFile    *os.File
	traceFile  *os.File
	signalChan chan os.Signal
}

var defaultDebug *Debug

func New(profileDir string) *Debug {
	if profileDir == "" {
		profileDir = defaultProfileDir
	}

	return &Debug{
		profileDir: profileDir,
		signalChan: make(chan os.Signal, 1),
	}
}

func (d *Debug) Start() error {
	if d.enabled {
		return fmt.Errorf("profiling already started")
	}

	runtime.SetCPUProfileRate(cpuProfileRate)

	if err := os.MkdirAll(d.profileDir, 0755); err != nil {
		return err
	}

	var timestamp = time.Now().Format(timeFormat)
	if err := d.startCPUProfiling(timestamp); err != nil {
		return fmt.Errorf("start cpu profiling error; %w", err)
	}

	d.startBlockAndMutexProfiling()

	if err := d.startTraceProfiling(timestamp); err != nil {
		return fmt.Errorf("start trace profiling error; %w", err)
	}

	d.enabled = true
	log.Println("profiling started successfully")

	return nil
}

func (d *Debug) SetupSignalHandler() {
	signal.Notify(d.signalChan, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT)
	go func() {
		<-d.signalChan

		log.Println("Signal received, stopping profiling and exiting...")
		d.Stop()
		os.Exit(0)
	}()
}

func (d *Debug) startCPUProfiling(timestamp string) error {
	cpuProfPath := fmt.Sprintf("%s/%s_%s.prof", d.profileDir, ProfileCPU, timestamp)

	var err error
	d.cpuFile, err = os.Create(cpuProfPath)
	if err != nil {
		return fmt.Errorf("create cpu profile file error; %w", err)
	}

	if err = pprof.StartCPUProfile(d.cpuFile); err != nil {
		if err = d.cpuFile.Close(); err != nil {
			return fmt.Errorf("close cpu profile file error; %w", err)
		}

		d.cpuFile = nil

		return fmt.Errorf("start cpu profile error; %w", err)
	}

	log.Printf("cpu profiling started, file: %s", cpuProfPath)
	return nil
}

func (d *Debug) startBlockAndMutexProfiling() {
	runtime.SetBlockProfileRate(blockProfileRate)
	log.Println("block profiling started")

	runtime.SetMutexProfileFraction(mutexProfileFraction)
	log.Println("mutex profiling started")
}

func (d *Debug) startTraceProfiling(timestamp string) error {
	var (
		traceProfPath = fmt.Sprintf("%s/%s_%s.out", d.profileDir, ProfileTrace, timestamp)
		err           error
	)
	d.traceFile, err = os.Create(traceProfPath)
	if err != nil {
		return fmt.Errorf("create trace profile file error; %w", err)
	}

	if err = trace.Start(d.traceFile); err != nil {
		if err = d.traceFile.Close(); err != nil {
			return fmt.Errorf("close trace profile file error; %w", err)
		}
		d.traceFile = nil

		return fmt.Errorf("start trace profile error; %w", err)
	}

	log.Printf("trace profiling started, file: %s", traceProfPath)
	return nil
}

func (d *Debug) Stop() {
	if !d.enabled {
		return
	}

	log.Println("stopping profiling and saving results...")

	d.stopCPUProfiling()
	d.stopTraceProfiling()

	var timestamp = time.Now().Format(timeFormat)

	d.saveProfile(ProfileMemory, timestamp)
	d.saveProfile(ProfileBlock, timestamp)
	d.saveProfile(ProfileMutex, timestamp)
	d.saveProfile(ProfileGoroutine, timestamp)

	d.enabled = false

	log.Println("profiling stopped and results saved")
}

func (d *Debug) stopCPUProfiling() {
	if d.cpuFile == nil {
		return
	}

	pprof.StopCPUProfile()

	if err := d.cpuFile.Close(); err != nil {
		log.Printf("cpu file close error; %v", err)
	} else {
		log.Println("cpu profiling stopped and saved")
	}

	d.cpuFile = nil
}

func (d *Debug) stopTraceProfiling() {
	if d.traceFile == nil {
		return
	}

	trace.Stop()

	if err := d.traceFile.Close(); err != nil {
		log.Printf("trace file close error; %v", err)
	} else {
		log.Println("trace profiling stopped and saved")
	}

	d.traceFile = nil
}

func (d *Debug) saveProfile(profileType ProfileType, timestamp string) {
	var profPath = fmt.Sprintf("%s/%s_%s.prof", d.profileDir, profileType, timestamp)
	profFile, err := os.Create(profPath)
	if err != nil {
		log.Printf("create profile file error; %v", err)
		return
	}
	defer func(profFile *os.File) {
		if err := profFile.Close(); err != nil {
			log.Printf("profile close error; %v", err)
		}
	}(profFile)

	var (
		lookupName string
		writeFunc  func(file *os.File) error
	)
	switch profileType {
	case ProfileMemory:
		writeFunc = func(file *os.File) error {
			return pprof.WriteHeapProfile(file)
		}
	case ProfileBlock, ProfileMutex, ProfileGoroutine:
		lookupName = string(profileType)
		writeFunc = func(file *os.File) error {
			return pprof.Lookup(lookupName).WriteTo(file, 0)
		}
	default:
		log.Printf("profile type %s is not supported", profileType)
		return
	}

	if err := writeFunc(profFile); err != nil {
		log.Printf("write %s profile error; %v", profileType, err)
	} else {
		log.Printf("%s profile saved to %s", profileType, profPath)
	}
}

func IsEnabled() bool {
	return defaultDebug != nil && defaultDebug.enabled
}

func SetupSignalHandler() {
	defaultDebug.SetupSignalHandler()
}

func Stop() {
	if defaultDebug == nil {
		return
	}

	defaultDebug.Stop()
}
