// Copyright 2020 Carsten Strotmann (sys4 AG). All rights reserved.
// Use of this source code is governed by a BSD-style license that can
// be found in the LICENSE file.

// A simple watchdog for a DNS resolver
// Based on chaos.go by Miek Gieben (see github.com/miekg/exdns)

package main

import (
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"strconv"
	"time"

	"github.com/miekg/dns"
)


var (
	failthresh   int
	failcnt      int
	sleep        int
	fverbose     bool
	nsaddr       string
	logseverity  string
	logfacility  string
	logpriority  syslog.Priority
	err          error
)

func init() {
	flag.StringVar(&nsaddr, "n", "127.0.0.1:53", "IP-Address and Port of Nameserver")
	flag.StringVar(&logseverity, "y", "NOTICE", "Syslog Severity (EMERG, ALERT, CRIT, ERR, WARNING, NOTICE, INFO, DEBUG)")
	flag.StringVar(&logfacility, "f", "SYSLOG", "Syslog Facility (KERN, USER, MAIL, DAEMON, AUTH, SYSLOG, LPR, NEWS, UUCP, CRON, AUTHPRIV, FTP, LOCAL[0-7])")
	flag.BoolVar(&fverbose, "v", false, "Verbose log output")
	flag.IntVar(&failthresh, "c", 3, "Failure Count until termination")
	flag.IntVar(&sleep,"s", 1, "Interval (seconds")
}

func main() {
	flag.Parse()

	failcnt = 0
	logpriority = 0

	switch logseverity {
	case "EMERG":
		logpriority = syslog.LOG_EMERG
	case "ALERT":
		logpriority = syslog.LOG_ALERT
	case "CRIT":
		logpriority = syslog.LOG_CRIT
	case "ERR":
		logpriority = syslog.LOG_ERR
	case "WARNING":
		logpriority = syslog.LOG_WARNING
	case "NOTICE":
		logpriority = syslog.LOG_NOTICE
	case "INFO":
		logpriority = syslog.LOG_INFO
	case "DEBUG":
		logpriority = syslog.LOG_DEBUG
	}

	switch logfacility {
	case "KERN":
		logpriority = logpriority | syslog.LOG_KERN
	case "USER":
		logpriority = logpriority | syslog.LOG_USER
	case "MAIL":
		logpriority = logpriority | syslog.LOG_MAIL
	case "DAEMON":
		logpriority = logpriority | syslog.LOG_DAEMON
	case "AUTH":
		logpriority = logpriority | syslog.LOG_AUTH
	case "SYSLOG":
		logpriority = logpriority | syslog.LOG_SYSLOG
	case "LPR":
		logpriority = logpriority | syslog.LOG_LPR
	case "NEWS":
		logpriority = logpriority | syslog.LOG_NEWS
	case "UUCP":
		logpriority = logpriority | syslog.LOG_UUCP
	case "CRON":
		logpriority = logpriority | syslog.LOG_CRON
	case "AUTHPRIV":
		logpriority = logpriority | syslog.LOG_AUTHPRIV
	case "FTP":
		logpriority = logpriority | syslog.LOG_FTP
	case "LOCAL0":
		logpriority = logpriority | syslog.LOG_LOCAL0
	case "LOCAL1":
		logpriority = logpriority | syslog.LOG_LOCAL1
	case "LOCAL2":
		logpriority = logpriority | syslog.LOG_LOCAL2
	case "LOCAL3":
		logpriority = logpriority | syslog.LOG_LOCAL3
	case "LOCAL4":
		logpriority = logpriority | syslog.LOG_LOCAL4
	case "LOCAL5":
		logpriority = logpriority | syslog.LOG_LOCAL5
	case "LOCAL6":
		logpriority = logpriority | syslog.LOG_LOCAL6
	case "LOCAL7":
		logpriority = logpriority | syslog.LOG_LOCAL7
	}

	if fverbose {
		fmt.Println("Syslog to           : " + logseverity + "/" + logfacility + " (" + strconv.Itoa(int(logpriority)) +")")
	}

	logwriter, e := syslog.New(syslog.LOG_NOTICE, "dns-watchdog")
	if e == nil {
		log.SetOutput(logwriter)
	}

	c := new(dns.Client)
	m := &dns.Msg{
		Question: make([]dns.Question, 1),
	}

	if fverbose {
		fmt.Println("Watching DNS Server : " + nsaddr)
	}

	for {
		m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, rtt, err := c.Exchange(m, nsaddr)

		if err != nil {
			fmt.Println(err)
			failcnt++
			log.Printf("Fail # %d ", failcnt)
			if failcnt > failthresh {
				log.Printf("Reached maximum failure count # %d, exit! ", failcnt)
				os.Exit(128)
			}

		} else {
			if fverbose {
				if in != nil && len(in.Answer) > 0 {
					log.Printf("(time %.3d µs) %v\n", rtt/1e3, in.Answer[0])
				}
			}
			failcnt = 0
		}
		time.Sleep(time.Duration(sleep) * time.Second)

	}
}
