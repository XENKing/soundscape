package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xenking/soundscape/internal/archiver"
	"github.com/xenking/soundscape/internal/logtailer"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/acme/autocert"
)

var (
	cli = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// flags
	backlink               string
	datadir                string
	debug                  bool
	showVersion            bool
	httpAddr               string
	httpAdmins             arrayFlags
	httpAdminUsers         []string
	httpReadOnlys          arrayFlags
	httpHost               string
	httpPrefix             string
	httpUsername           string
	letsencrypt            bool
	reverseProxyAuthHeader string
	reverseProxyAuthIP     string

	// set based on httpAddr
	httpIP   string
	httpPort string

	// logging
	logger  *zap.SugaredLogger
	logtail *logtailer.Logtailer

	// archiver
	archive *archiver.Archiver

	// secrets
	authsecret *Secret

	// config
	config *Config

	// version
	version string
)

func init() {
	dbInit()
	cli.StringVar(&backlink, "backlink", "", "backlink (optional)")
	cli.StringVar(&datadir, "data-dir", "/data", "data directory")
	cli.BoolVar(&debug, "debug", false, "debug mode")
	cli.BoolVar(&showVersion, "version", false, "display version and exit")
	cli.StringVar(&httpAddr, "http-addr", ":80", "listen address")
	cli.StringVar(&httpHost, "http-host", "", "HTTP host")
	cli.StringVar(&httpUsername, "http-username", "soundscape", "HTTP basic auth username")
	cli.Var(&httpAdmins, "http-admin", "HTTP basic auth user/password for admins.")
	cli.Var(&httpReadOnlys, "http-read-only", "HTTP basic auth user/password for read only users.")
	cli.StringVar(&httpPrefix, "http-prefix", "/soundscape", "HTTP URL prefix (not actually supported yet!)")
	cli.BoolVar(&letsencrypt, "letsencrypt", false, "enable TLS using Let's Encrypt")
	cli.StringVar(&reverseProxyAuthHeader, "reverse-proxy-header", "X-Authenticated-User", "reverse proxy auth header")
	cli.StringVar(&reverseProxyAuthIP, "reverse-proxy-ip", "", "reverse proxy auth IP")
}

func main() {
	var err error

	cli.Parse(os.Args[1:])

	if showVersion {
		fmt.Printf("Soundscape version: %s", version)
		os.Exit(0)
	}

	// Create users in db if not exists, or set password and role if needed
	for _, httpUser := range httpAdmins {
		split := strings.Split(httpUser, ":")
		httpUsername := split[0]
		httpUserPassword := split[1]
		hasher := sha512.New()
		hasher.Write([]byte(httpUserPassword))
		httpAdminUsers = append(httpAdminUsers, httpUsername)
		var user User
		db.Where(User{Username: httpUsername}).Assign(User{Password: hex.EncodeToString(hasher.Sum(nil)), Role: "admin"}).FirstOrCreate(&user)
	}
	for _, httpUser := range httpReadOnlys {
		split := strings.Split(httpUser, ":")
		httpUsername := split[0]
		httpUserPassword := split[1]
		hasher := sha512.New()
		hasher.Write([]byte(httpUserPassword))
		var user User
		db.Where(User{Username: httpUsername}).Assign(User{Password: hex.EncodeToString(hasher.Sum(nil)), Role: "readonly"}).FirstOrCreate(&user)
	}

	// logtailer
	logtail, err = logtailer.NewLogtailer(200 * 1024)
	if err != nil {
		panic(err)
	}

	// logger
	atomlevel := zap.NewAtomicLevel()
	l := zap.New(
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
			zapcore.NewMultiWriteSyncer(zapcore.Lock(zapcore.AddSync(os.Stdout)), logtail),
			atomlevel,
		),
	)
	defer l.Sync()
	logger = l.Sugar()

	// debug logging
	if debug {
		atomlevel.SetLevel(zap.DebugLevel)
	}
	logger.Debugf("debug logging is enabled")

	// config
	config, err = NewConfig("config.json")
	if err != nil {
		logger.Fatal(err)
	}

	// archiver
	archive = archiver.NewArchiver(datadir, 2, logger)

	// datadir
	datadir = filepath.Clean(datadir)
	if _, err := os.Stat(datadir); err != nil {
		logger.Debugf("creating datadir %q", datadir)
		if err := os.MkdirAll(datadir, 0755); err != nil {
			logger.Fatal(err)
		}

		// default playlist
		lists, err := ListLists()
		if err != nil {
			logger.Fatal(err)
		}
		if len(lists) == 0 {
			_, err := NewList("My Music")
			if err != nil {
				logger.Fatal(err)
			}
		}
	}

	// remove any temporary transcode files
	tmpfiles, _ := filepath.Glob(datadir + "/*.transcoding")
	for _, tmpfile := range tmpfiles {
		logger.Debugf("removing %q", tmpfile)
		if err := os.Remove(tmpfile); err != nil {
			logger.Errorf("removing %q failed: %s", tmpfile, err)
		}
	}

	// usage
	usage := func(msg string) {
		fmt.Fprintf(os.Stderr, "ERROR: "+msg+"\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s --http-host music.example.com\n\n", os.Args[0])
		cli.PrintDefaults()
		os.Exit(1)
	}

	// http admin
	if httpAdmins == nil && reverseProxyAuthIP == "" {
		usage("the --http-admin or the --reverseProxyAuthIP flag is required")
	}

	// http host
	if httpHost == "" {
		usage("the --http-host flag is required")
	}
	httpPrefix = strings.TrimRight(httpPrefix, "/")

	// http port
	httpIP, httpPort, err := net.SplitHostPort(httpAddr)
	if err != nil {
		usage("invalid --http-addr: " + err.Error())
	}

	// auth secret is the password for basic auth
	if reverseProxyAuthIP == "" {
		authsecret = NewSecret(filepath.Join(datadir, ".authsecret"))
	}

	//
	// Routes
	//
	r := httprouter.New()
	r.RedirectTrailingSlash = false
	r.RedirectFixedPath = false
	r.HandleMethodNotAllowed = false

	// Handlers
	r.GET("/", Log(Auth(index, "admin")))
	r.GET(Prefix("/logs"), Log(Auth(logs, "admin")))
	r.GET(Prefix("/"), Log(Auth(home, "readonly")))
	r.GET(Prefix(""), Log(Auth(home, "readonly")))

	// Login
	r.GET(Prefix("/login"), Log(Auth(loginHandler, "none")))
	r.POST(Prefix("/login"), Log(Auth(loginHandler, "none")))

	// Logout
	r.GET(Prefix("/logout"), Log(Auth(logoutHandler, "none")))

	// Help
	r.GET(Prefix("/help"), Log(Auth(help, "none")))

	// Library
	r.GET(Prefix("/library"), Log(Auth(library, "readonly")))

	// Media
	r.GET(Prefix("/media/thumbnail/:media"), Log(Auth(thumbnailMedia, "readonly")))
	r.GET(Prefix("/media/view/:media"), Log(Auth(viewMedia, "readonly")))
	r.GET(Prefix("/media/delete/:media"), Log(Auth(deleteMedia, "admin")))
	r.GET(Prefix("/media/access/:filename"), Auth(streamMedia, "readonly"))
	r.GET(Prefix("/media/download/:media"), Auth(downloadMedia, "readonly"))

	// Publicly accessible streaming (using playlist id as "auth")
	r.GET(Prefix("/stream/:list/:filename"), Auth(streamMedia, "none"))

	// Import
	r.GET(Prefix("/import"), Log(Auth(importHandler, "admin")))

	// Archiver
	r.GET(Prefix("/archiver/jobs"), Auth(archiverJobs, "admin"))
	r.POST(Prefix("/archiver/save/:id"), Log(Auth(archiverSave, "admin")))
	r.GET(Prefix("/archiver/cancel/:id"), Log(Auth(archiverCancel, "admin")))

	// List
	r.GET(Prefix("/create"), Log(Auth(createList, "admin")))
	r.POST(Prefix("/create"), Log(Auth(createList, "admin")))
	r.POST(Prefix("/add/:list/:media"), Log(Auth(addMediaList, "admin")))
	r.POST(Prefix("/remove/:list/:media"), Log(Auth(removeMediaList, "admin")))
	r.GET(Prefix("/remove/:list/:media"), Log(Auth(removeMediaList, "admin")))

	r.GET(Prefix("/edit/:id"), Log(Auth(editList, "admin")))
	r.POST(Prefix("/edit/:id"), Log(Auth(editList, "admin")))
	r.GET(Prefix("/shuffle/:id"), Log(Auth(shuffleList, "admin")))
	r.GET(Prefix("/play/:id"), Log(Auth(playList, "none")))
	r.GET(Prefix("/m3u/:id"), Log(Auth(m3uList, "none")))
	r.GET(Prefix("/podcast/:id"), Log(Auth(podcastList, "none")))

	r.POST(Prefix("/config"), Log(Auth(configHandler, "admin")))

	r.GET(Prefix("/delete/:id"), Log(Auth(deleteList, "admin")))

	// API
	r.GET(Prefix("/v1/status"), Log(Auth(v1status, "none")))

	// Subsonic API
	r.GET("/rest/ping.view", Log(Auth(subsonicPing, "none")))
	r.POST("/rest/ping.view", Log(Auth(subsonicPing, "none")))

	r.GET("/rest/getMusicFolders.view", Log(Auth(subsonicGetMusicFolders, "none")))
	r.POST("/rest/getMusicFolders.view", Log(Auth(subsonicGetMusicFolders, "none")))

	r.GET("/rest/getIndexes.view", Log(Auth(subsonicGetIndexes, "none")))
	r.POST("/rest/getIndexes.view", Log(Auth(subsonicGetIndexes, "none")))

	r.GET("/rest/getPlaylists.view", Log(Auth(subsonicGetPlaylists, "none")))
	r.POST("/rest/getPlaylists.view", Log(Auth(subsonicGetPlaylists, "none")))

	r.GET("/rest/getPlaylist.view", Log(Auth(subsonicGetPlaylist, "none")))
	r.POST("/rest/getPlaylist.view", Log(Auth(subsonicGetPlaylist, "none")))

	r.GET("/rest/getCoverArt.view", Log(Auth(subsonicGetCoverArt, "none")))
	r.POST("/rest/getCoverArt.view", Log(Auth(subsonicGetCoverArt, "none")))

	r.GET("/rest/getLyrics.view", Log(Auth(subsonicGetLyrics, "none")))
	r.POST("/rest/getLyrics.view", Log(Auth(subsonicGetLyrics, "none")))

	// Assets
	r.GET(Prefix("/static/*path"), Auth(staticAsset, "none")) // TODO: Auth() but by checking Origin/Referer for a valid playlist ID?
	r.GET(Prefix("/logo.png"), Log(Auth(logo, "none")))

	//
	// Server
	//
	httpTimeout := 48 * time.Hour
	maxHeaderBytes := 10 * (1024 * 1024) // 10 MB

	// Plain text web server.
	if !letsencrypt {
		httpd := &http.Server{
			Handler:        r,
			Addr:           httpAddr,
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}

		hostport := net.JoinHostPort(httpHost, httpPort)
		if httpPort == "80" {
			hostport = httpHost
		}
		logger.Infof("Soundscape version: %s %s", version, &url.URL{
			Scheme: "http",
			Host:   hostport,
			Path:   httpPrefix + "/",
		})

		if authsecret != nil {
			logger.Infof("Login credentials:  %s  /  %s", httpUsername, authsecret.Get())
		}
		logger.Fatal(httpd.ListenAndServe())
	}

	// Let's Encrypt TLS mode

	// autocert
	certmanager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(filepath.Join(datadir, ".autocert")),
		HostPolicy: autocert.HostWhitelist(httpHost, "www."+httpHost),
	}

	// http redirect to https and Let's Encrypt auth
	go func() {
		redir := httprouter.New()
		redir.GET("/*path", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
			r.URL.Scheme = "https"
			r.URL.Host = net.JoinHostPort(httpHost, httpPort)
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
		})

		httpd := &http.Server{
			Handler:        certmanager.HTTPHandler(redir),
			Addr:           net.JoinHostPort(httpIP, "80"),
			WriteTimeout:   httpTimeout,
			ReadTimeout:    httpTimeout,
			MaxHeaderBytes: maxHeaderBytes,
		}
		if err := httpd.ListenAndServe(); err != nil {
			logger.Fatalf("http server on port 80 failed: %s", err)
		}
	}()

	// TLS
	tlsConfig := tls.Config{
		GetCertificate:           certmanager.GetCertificate,
		NextProtos:               []string{"http/1.1"},
		Rand:                     rand.Reader,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Override default for TLS.
	if httpPort == "80" {
		httpPort = "443"
		httpAddr = net.JoinHostPort(httpIP, httpPort)
	}

	httpsd := &http.Server{
		Handler:        r,
		Addr:           httpAddr,
		WriteTimeout:   httpTimeout,
		ReadTimeout:    httpTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}

	// Enable TCP keep alives on the TLS connection.
	tcpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		logger.Fatalf("listen failed: %s", err)
		return
	}
	tlsListener := tls.NewListener(tcpKeepAliveListener{tcpListener.(*net.TCPListener)}, &tlsConfig)

	hostport := net.JoinHostPort(httpHost, httpPort)
	if httpPort == "443" {
		hostport = httpHost
	}
	logger.Infof("Soundscape version: %s %s", version, &url.URL{
		Scheme: "https",
		Host:   hostport,
		Path:   httpPrefix + "/",
	})
	logger.Infof("Login credentials:  %s  /  %s", httpUsername, authsecret.Get())
	logger.Fatal(httpsd.Serve(tlsListener))
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (l tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := l.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(10 * time.Minute)
	return tc, nil
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}