package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"time"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/xenking/soundscape/internal/archiver"
	"github.com/xenking/soundscape/internal/youtube"

	"github.com/dgrijalva/jwt-go"
	"github.com/disintegration/imaging"
	"github.com/eduncan911/podcast"
	"github.com/xenking/ytdl"
	"github.com/julienschmidt/httprouter"
)

type Response struct {
	Config   Config
	Request  *http.Request
	Params   *httprouter.Params
	HTTPHost string
	HTTPPrefix string
	Version  string
	Backlink string
	DiskInfo *DiskInfo
	Archiver *archiver.Archiver

	Error   string
	User    string
	IsAdmin string
	Section string

	// Paging
	Page       int64
	Pages      []int64
	Limit      int64
	Total      int64
	GrandTotal int64

	// Search
	Query string

	List   *List
	Lists  []*List
	Media  *Media
	Medias []*Media

	ActiveMedias []*Media
	QueuedMedias []*Media

	Youtubes []youtube.Video
}

const secretKey string = "ThisIsTooSecret"

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func NewResponse(r *http.Request, ps httprouter.Params) *Response {
	diskInfo, err := NewDiskInfo(datadir)
	if err != nil {
		panic(err)
	}
	return &Response{
		Config:   config.Get(),
		Request:  r,
		Params:   &ps,
		User:     ps.ByName("user"),
		IsAdmin:  ps.ByName("role"),
		HTTPHost: httpHost,
		HTTPPrefix: httpPrefix,
		Version:  version,
		Backlink: backlink,
		DiskInfo: diskInfo,
		Archiver: archive,
	}
}

func clearSession(w *http.ResponseWriter) {
	deleteCookie := http.Cookie{Name: "X-Soundscape-Token", Value: "none", Expires: time.Now(), HttpOnly: true}
	http.SetCookie(*w, &deleteCookie)
	return
}

func logs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, line := range logtail.Lines() {
		fmt.Fprintf(w, "%s\n", line)
	}
}

func index(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	Redirect(w, r, "/")
}

/*func createUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// Create a user
	u1 := User{Username: "admin", Password: "admin"}
	db.Create(&u1)
	fmt.Fprintln(w, "user created")
}
*/
func home(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// Accept TOS
	if r.FormValue("tos") == "yes" {
		if err := config.SetAcceptTOS(true); err != nil {
			Error(w, err)
			return
		}
	}
	// Require TOS
	if !config.Get().AcceptTOS {
		Redirect(w, r, "/help")
		return
	}

	lists, err := ListLists()
	if err != nil {
		Error(w, err)
		return
	}
	res := NewResponse(r, ps)
	res.Lists = lists
	res.Section = "home"
	HTML(w, "home.html", res)
}

func configHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	key := r.FormValue("key")
	value := r.FormValue("value")

	switch key {
	case "volume":
		n, err := strconv.ParseFloat(value, 32)
		if err != nil {
			Error(w, err)
			return
		}
		if err := config.SetVolume(float32(n)); err != nil {
			Error(w, err)
			return
		}
	}
	JSON(w, "OK")
}

func importHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var youtubes []youtube.Video
	query := strings.TrimSpace(r.FormValue("q"))

	if query != "" {
		yt, err := youtube.Search(query)
		if err != nil {
			logger.Errorf("query %q failed: %s", query, err)
		} else {
			youtubes = append(youtubes, yt...)
		}
	}

	var filtered []youtube.Video
	for _, v := range youtubes {
		// Already exists in library, so filter it out.
		if m, err := loadMedia(v.ID); err == nil {
			if m.HasAudio() || archive.InProgress(m.ID) {
				continue
			}
		}
		filtered = append(filtered, v)
	}
	youtubes = filtered

	res := NewResponse(r, ps)
	res.Query = query
	res.Youtubes = youtubes
	res.Section = "import"
	HTML(w, "import.html", res)
}

func help(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	res := NewResponse(r, ps)
	res.Section = "help"
	HTML(w, "help.html", res)
}

func loginHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	if r.Method == "GET" {
		res := NewResponse(r, ps)
		res.Section = "login"
		HTML(w, "login.html", res)
		return
	}

	var juser string
	username := r.FormValue("username")
	password := r.FormValue("password")

	// If token, refresh it and send response
	reqToken, tokErr := r.Cookie("X-Soundscape-Token")
	if tokErr != http.ErrNoCookie {
		token, err := jwt.Parse(reqToken.Value, func(t *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		})
		if err == nil && token.Valid {
			juser = token.Claims.(jwt.MapClaims)["user"].(string)
			ps = append(ps, httprouter.Param{Key: "user", Value: juser})
			ps = append(ps, httprouter.Param{Key: "role", Value: "admin"})
			w.Header().Set("X-Soundscape-Token", "*")
			Redirect(w, r, "/")
			return
		} else {
			Redirect(w, r, "/logout")
			return
		}
	} else {
		var dbuser User
		if err := db.Where(&User{Username: username}).First(&dbuser).Error; err != nil {
			// user doesn't exists
			Redirect(w, r, "/logout")
			return
		} else {
			// user exists, check password
			hasher := sha512.New()
			hasher.Write([]byte(password))
			newHash := hex.EncodeToString(hasher.Sum(nil))
			if dbuser.Password != newHash {
				// Bad password
				Redirect(w, r, "/logout")
				return
			} else {
				// Good password
				// Create JWT token
				token := jwt.New(jwt.GetSigningMethod("HS256"))
				claims := make(jwt.MapClaims)
				claims["user"] = dbuser.Username
				claims["exp"] = time.Now().Add(time.Minute * 3600).Unix()
				token.Claims = claims
				tokenString, err := token.SignedString([]byte(secretKey))
				ps = append(ps, httprouter.Param{Key: "user", Value: username})
				ps = append(ps, httprouter.Param{Key: "role", Value: "admin"})
				if err != nil {
					panic(err)
				}
				w.Header().Set("X-Soundscape-Token", "*")
				expireCookie := time.Now().Add(time.Hour * 72)
				cookie := http.Cookie{Name: "X-Soundscape-Token", Value: tokenString, Expires: expireCookie, HttpOnly: true}
				http.SetCookie(w, &cookie)
				Redirect(w, r, "/")
				return
			}
		}
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	clearSession(&w)
	Redirect(w, r, "/login")
}

func library(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	medias, err := ListMedias()
	if err != nil {
		Error(w, err)
		return
	}

	grandTotal := int64(len(medias))

	query := r.FormValue("q")

	// Filter
	if query != "" {
		var filtered []*Media
		for _, m := range medias {
			content := m.Title
			content += m.Description
			content += m.Author
			content += m.Source
			if !strings.Contains(strings.ToLower(content), strings.ToLower(query)) {
				continue
			}
			filtered = append(filtered, m)
		}
		medias = filtered
	}

	// pagination
	var limit int64 = 10
	page, _ := strconv.ParseInt(r.FormValue("p"), 10, 64)
	if page < 1 {
		page = 1
	}

	total := int64(len(medias))
	switch {
	case total > 100:
		limit = 20
	case total > 500:
		limit = 50
	case total > 1000:
		limit = 100
	}
	pages := []int64{}
	var lastpage = (total / limit) + 1
	for i := int64(1); i <= lastpage; i++ {
		pages = append(pages, i)
	}
	if page > lastpage {
		page = lastpage
	}

	// chunk
	var begin = (page - 1) * limit
	var end = begin + limit
	if end > total {
		end = total
	}

	lists, err := ListLists()
	if err != nil {
		Error(w, err)
		return
	}

	res := NewResponse(r, ps)
	res.Medias = medias[begin:end]
	res.Lists = lists
	res.Page = page
	res.Pages = pages
	res.Query = query
	res.Limit = limit
	res.Total = total
	res.GrandTotal = grandTotal
	res.Section = "library"
	HTML(w, "library.html", res)
}

//
// Media
//

func thumbnailMedia(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	media, err := FindMedia(ps.ByName("media"))
	if err != nil {
		Error(w, err)
		return
	}

	img, err := imaging.Open(media.ImageFile())
	if err != nil {
		Error(w, err)
		return
	}

	img = imaging.Resize(img, 320, 0, imaging.Lanczos)

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Vary", "Accept-Encoding")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", 7*86400))
	if err := imaging.Encode(w, img, imaging.JPEG); err != nil {
		Error(w, err)
		return
	}
}

func viewMedia(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	media, err := FindMedia(ps.ByName("media"))
	if err != nil {
		Error(w, err)
		return
	}

	res := NewResponse(r, ps)
	res.Media = media
	res.Section = "view"
	HTML(w, "view.html", res)
}

func deleteMedia(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if err := DeleteMedia(ps.ByName("media")); err != nil {
		Error(w, err)
		return
	}
	Redirect(w, r, "/library?p=%s&q=%s&message=mediadeleted", r.FormValue("p"), r.FormValue("q"))
}

func downloadMedia(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	media, err := FindMedia(ps.ByName("media"))
	if err != nil {
		Error(w, err)
		return
	}
	filename := filepath.Join(datadir, media.ID+".m4a")
	nicename := strings.Trim(media.Title, `"`) + ".m4a"

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", nicename))
	http.ServeFile(w, r, filename)
}

func streamMedia(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	filename := filepath.Join(datadir, ps.ByName("filename"))
	if id := ps.ByName("list"); id != "" {
		if _, err := FindList(id); err != nil {
			Error(w, err)
			return
		}
	}
	if strings.HasSuffix(filename, ".m4a") {
		w.Header().Set("Content-Type", "video/mp4")
	}
	http.ServeFile(w, r, filename)
}

//
// Archiver
//

func archiverJobs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	res := NewResponse(r, ps)
	res.ActiveMedias = ActiveMedias()
	res.QueuedMedias = QueuedMedias()
	HTML(w, "jobs.html", res)
}

func archiverSave(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	source := fmt.Sprintf("https://www.youtube.com/v?id=%s", id)

	vinfo, err := ytdl.GetVideoInfoFromID(id)
	if err != nil {
		Error(w, err)
		return
	}

	media, err := NewMedia(vinfo.ID, vinfo.Author, vinfo.Title, int64(vinfo.Duration.Seconds()), source)
	if err != nil {
		Error(w, err)
		return
	}
	logger.Infof("created new media %q %q %d", media.ID, media.Title, media.Length)

	archive.Add(id, source)
	JSON(w, "OK")
}

func archiverCancel(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	archive.Remove(ps.ByName("id"))
	Redirect(w, r, "/import?message=savecancelled")
}

func deleteList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	list, err := FindList(ps.ByName("id"))
	if err != nil {
		Error(w, err)
		return
	}
	if err := DeleteList(list.ID); err != nil {
		Error(w, err)
		return
	}
	Redirect(w, r, "/?message=playlistdeleted")
}

func podcastList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	list, err := FindList(ps.ByName("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = r.Method
	}
	if proto != "http" {
		proto = "https"
	}
	baseurl := fmt.Sprintf("%s://%s%s", proto, httpHost, httpPrefix)

	p := podcast.New(list.Title, baseurl, list.Title, &list.Created, &list.Modified)
	p.AddAuthor(httpHost, "soundscape@"+httpHost)
	p.AddImage(baseurl + "/logo.png")

	for _, media := range list.Medias {
		typ := podcast.M4V
		ext := "m4a"
		filename := media.AudioFile()

		fileInfo, err := os.Stat(filename)
		if err != nil {
			logger.Error(err)
			continue
		}

		streamurl, err := url.Parse(fmt.Sprintf("%s/stream/%s/%s.%s", baseurl, list.ID, media.ID, ext))
		if err != nil {
			Error(w, err)
			return
		}

		item := podcast.Item{
			Title:       fmt.Sprintf("%s - %s", media.Title, media.Author),
			Description: fmt.Sprintf("%s\n\n%s", media.Description, media.Created),
			PubDate:     &media.Created,
		}
		item.AddEnclosure(streamurl.String(), typ, fileInfo.Size())
		if _, err := p.AddItem(item); err != nil {
			Error(w, err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	if err := p.Encode(w); err != nil {
		Error(w, err)
	}
}

func m3uList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	list, err := FindList(ps.ByName("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ext := ".m4a"

	w.Header().Set("Content-Type", "application/mpegurl")
	fmt.Fprintf(w, "#EXTM3U\n")
	for _, media := range list.Medias {
		fmt.Fprintf(w, "#EXTINF:%d,%s\n", media.Length, media.Title)
		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = "https"
		}
		fmt.Fprintf(w, "%s://%s%s/stream/%s/%s%s\n", proto, httpHost, httpPrefix, list.ID, media.ID, ext)
	}
}

func playList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	list, err := FindList(ps.ByName("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	res := NewResponse(r, ps)
	res.List = list
	res.Section = "play"
	var medias []*Media
	db.Model(&list).Related(&medias, "Medias")
	logger.Debugf("select playlist %q", medias)
	res.Medias = medias
	HTML(w, "play.html", res)
}

func createList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if r.Method == "GET" {
		res := NewResponse(r, ps)
		res.Section = "create"
		HTML(w, "create.html", res)
		return
	}

	title := strings.TrimSpace(r.FormValue("title"))

	if title == "" {
		Redirect(w, r, "/create")
		return
	}

	_, err := NewList(title)
	if err != nil {
		Error(w, err)
		return
	}
	Redirect(w, r, "/library?message=playlistadded")
}

func removeMediaList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	media, err := FindMedia(ps.ByName("media"))
	if err != nil {
		Error(w, err)
		return
	}
	list, err := FindList(ps.ByName("list"))
	if err != nil {
		Error(w, err)
		return
	}
	if err := list.RemoveMedia(media); err != nil {
		Error(w, err)
		return
	}
	Redirect(w, r, "/edit/%s", list.ID)
}

func addMediaList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	media, err := FindMedia(ps.ByName("media"))
	if err != nil {
		Error(w, err)
		return
	}

	list, err := FindList(ps.ByName("list"))
	if err != nil {
		Error(w, err)
		return
	}

	list.AddMedia(media)
	JSON(w, "OK")
}

func shuffleList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	list, err := FindList(ps.ByName("id"))
	if err != nil {
		Error(w, err)
		return
	}
	if err := list.ShuffleMedia(); err != nil {
		Error(w, err)
		return
	}

	Redirect(w, r, "/play/%s", list.ID)
}

func editList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	list, err := FindList(ps.ByName("id"))
	if err != nil {
		Error(w, err)
		return
	}

	res := NewResponse(r, ps)
	res.List = list
	res.Section = "edit"
	var medias []*Media
	db.Model(&list).Related(&medias, "Medias")
	logger.Debugf("edit list %q", medias)
	res.Medias = medias
	HTML(w, "edit.html", res)
}

func staticAsset(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	serveAsset(w, r, ps.ByName("path"))
}

func logo(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	serveAsset(w, r, "/logo.png")
}

func serveAsset(w http.ResponseWriter, r *http.Request, filename string) {
	path := "static" + filename

	b, err := Asset(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fi, err := AssetInfo(path)
	if err != nil {
		Error(w, err)
		return
	}
	http.ServeContent(w, r, path, fi.ModTime(), bytes.NewReader(b))
}

//
// API
//
func v1status(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// localhost only.
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip != "::1" && ip != "127.0.0.1" {
		http.NotFound(w, r)
		return
	}
	status := "idle"
	if len(QueuedMedias()) > 0 || len(ActiveMedias()) > 0 {
		status = "busy"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%s\n", status)
}
