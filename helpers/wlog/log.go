package wlog

import (
	"log"
	"strconv"
	"strings"
)

const (
	NOLOG int = iota
	ERROR
	WARN
	INFO
	DEBUG
	TRACE
	TRALL
)

var levelByName = map[string]int{
	"disabled": NOLOG,
	"error":    ERROR,
	"warn":     WARN,
	"info":     INFO,
	"debug":    DEBUG,
	"trace":    TRACE,
	"traceall": TRALL,
}

type Wlogger struct {
	level int
}

func NewWrappedLogger(env string, defaultLevel int) *Wlogger {
	wl := &Wlogger{defaultLevel}
	if level, ok := levelByName[strings.ToLower(env)]; ok {
		wl.SetLevel(level)
	} else if level, err := strconv.Atoi(env); err == nil {
		wl.SetLevel(level)
	}
	return wl
}

func (wl *Wlogger) SetLevel(level int) {
	if level < NOLOG {
		wl.level = NOLOG
	} else {
		wl.level = min(level, TRALL)
	}
}

func (wl *Wlogger) GetLevel() int {
	return wl.level
}

func (wl *Wlogger) Print(level int, v ...any) {
	if wl.level < level {
		return
	}
	log.Print(v...)
}

func (wl *Wlogger) Println(level int, v ...any) {
	if wl.level < level {
		return
	}
	log.Println(v...)
}

func (wl *Wlogger) Printf(level int, format string, v ...any) {
	if wl.level < level {
		return
	}
	log.Printf(format, v...)
}

func Print(v ...any) {
	log.Print(v...)
}

func Println(v ...any) {
	log.Println(v...)
}

func Printf(format string, v ...any) {
	log.Printf(format, v...)
}

func Fatalln(v ...any) {
	log.Fatalln(v...)
}

func Panic(v ...any) {
	log.Panic(v...)
}

func Panicf(format string, v ...any) {
	log.Panicf(format, v...)
}
