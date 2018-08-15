package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"crypto/tls"
	"crypto/x509"

	"github.com/alecthomas/kingpin"
	"github.com/elazarl/goproxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	caFile        = kingpin.Flag("cacert", "Path to the CA bundle").Required().String()
	keyFile       = kingpin.Flag("privkey", "Path to the private key").Required().String()
	certFile      = kingpin.Flag("cert", "Path to the client cert").Required().String()
	listen        = kingpin.Flag("listen", "Port to listen to").Default("127.0.0.1:8811").String()
	metricslisten = kingpin.Flag("metrics-listen", "Port to listen to for metrics").Default(":8812").String()
	reload        = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "proxy_last_ssl_certs_reload_timestamp",
			Help: "Last SSL certs reload.",
		},
	)
	requests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "proxy_requests_started_total",
			Help: "Total of proxy responses.",
		},
	)
	responses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Total of proxy responses.",
		},
		[]string{"code"},
	)
	inFlight = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "proxy_inflight",
			Help: "Proxy in flight requests.",
		},
	)
	verbose = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "proxy_verbose_bool",
			Help: "Is verbose active?.",
		},
	)
)

func init() {
	prometheus.MustRegister(inFlight)
	prometheus.MustRegister(requests)
	prometheus.MustRegister(responses)
	prometheus.MustRegister(reload)
	prometheus.MustRegister(verbose)
	commonCodes := []string{"200", "500", "503"}
	for _, c := range commonCodes {
		responses.WithLabelValues(c)
	}
}

func loadCertificates(proxy *goproxy.ProxyHttpServer) {
	log.Info("Loading Certs")
	tlsConfig, err := getTlsConfig()
	if err != nil {
		log.Fatal(err)
	}
	proxy.Tr = &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   90 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
	}
	reload.SetToCurrentTime()
}

func main() {
	kingpin.Parse()
	proxy := goproxy.NewProxyHttpServer()

	loadCertificates(proxy)
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	signal.Notify(c, syscall.SIGUSR1)
	go func() {
		for sig := range c {
			log.Infof("Got %v", sig)
			if sig == syscall.SIGHUP {
				loadCertificates(proxy)
			}
			if sig == syscall.SIGUSR1 {
				proxy.Verbose = !proxy.Verbose
				log.Infof("Setting Verbosity to %v", proxy.Verbose)
				if proxy.Verbose {
					verbose.Set(1)
				} else {
					verbose.Set(0)
				}
			}
		}
	}()

	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		inFlight.Inc()
		requests.Inc()
		if req.URL.Scheme == "http" {
			req.URL.Scheme = "https"
		}
		return req, nil
	})

	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		inFlight.Dec()
		if resp != nil {
			responses.WithLabelValues(fmt.Sprintf("%d", resp.StatusCode)).Inc()
		} else {
			responses.WithLabelValues("nil").Inc()
		}
		return resp
	})

	log.Infof("Starting proxy on %s", *metricslisten)

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Fatal(http.ListenAndServe(*metricslisten, nil))
	}()
	log.Infof("Starting proxy on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, proxy))
}

func getTlsConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: false}

	if len(*caFile) > 0 {
		caCertPool := x509.NewCertPool()
		caCert, err := ioutil.ReadFile(*caFile)
		if err != nil {
			return nil, fmt.Errorf("unable to use specified CA cert %s: %s", *caFile, err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to use specified client cert (%s) & key (%s): %s", *certFile, *keyFile, err)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	return tlsConfig, nil
}
