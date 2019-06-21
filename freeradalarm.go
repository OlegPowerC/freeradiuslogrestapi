package main

import (
	"log"
	"github.com/howeyc/fsnotify"
	"os"
	"fmt"
	"time"
	"strings"
	"io/ioutil"
	"encoding/json"
	"net/http"
	"sync"
	"runtime"
	"path/filepath"
)

const badmessage = "MSGBAD&&&"
const separator = "DELIM&&&"
/*
radius-server attribute 31 send nas-port-detail

nano /etc/raddb/radiusd.conf
        msg_goodpass = "MSGGOOD&&&Username:%{User-Name}DELIM&&&Packet from IP:%{Packet-Src-IP-Address}DELIM&&&Calling station ID:%{Calling-Station-Id}"
        msg_badpass = "MSGBAD&&&Username:%{User-Name}DELIM&&&Packet from IP:%{Packet-Src-IP-Address}DELIM&&&Calling station ID:%{Calling-Station-Id}"
*/

//Описание JSON параметров
type params struct {
	Ipaddrandport string `json:"ipport"`
	Filename string `json:"filename"`
	Debugmode int `json:"debugg"`
}

type alarm struct {
	Name string `json:"name"`
	Error  int    `json:"error"`
}

var mmes *alarm = &alarm{
	Name: "Free Radius",
	Error:  0,
}

type WrongAuth struct {
	Username string `json:"Username"`
	Packetfrom string `json:"Packet_SRC_IP"`
	Calling_station_id string `json:"Calling_Stetion_ID"`
}

type BadUserLog struct {
	BadUsers []WrongAuth
}

var mmymutex sync.Mutex
var BadUsersl BadUserLog
var debugmode bool = false
var errorgettimeout int64 = 0

func waitfsevent(watcher *fsnotify.Watcher,fname string){
	var prevsize int64 = 0
	var prevtime int64 = 0
	fis, err := os.Stat(fname);
	if err != nil {
		log.Fatal(err)
	}
	prevsize = fis.Size();

	for {
		select {
		case ev := <-watcher.Event:
			if ev.IsModify(){
				f,_ := os.Open(fname)
				f.Seek(prevsize,0)
				fi, err := os.Stat(fname);
				if err != nil {
					log.Fatal(err)
				}
				// get the size
				size := fi.Size()
				if size > prevsize{
					newdata_len := size-prevsize;
					buff := make([]byte,newdata_len)
					f.Read(buff)

					prevsize = size

					strfind := string(buff)

					curtime := time.Now().Unix()
					if strings.Contains(strfind,badmessage){
						addbaduser(strfind,&BadUsersl.BadUsers)
						deltatime := curtime - prevtime
						if deltatime < 30{
							fmt.Println("Wrong Password repeat")
							mmes.Error = 2
							errorgettimeout = curtime
						}
					}
					prevtime = curtime
				}
			}
		case err := <-watcher.Error:
			log.Println("error:", err)
		}
	}
}

func JsHandler(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		j, _ := json.Marshal(mmes)
		w.Write(j)
		ctime := time.Now().Unix()
		cdelta := ctime - errorgettimeout
		if mmes.Error == 2{
			if cdelta > 180 {
				mmes.Error = 0
			}
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "No method")
	}
}

func addbaduser(logstringbuffer string,mapp *[]WrongAuth){
	if debugmode {
		fmt.Println(logstringbuffer)
	}

	loglines := strings.Split(logstringbuffer,"\n")
	for _,logstringbufferst := range loglines{
		if debugmode{
			fmt.Println(logstringbufferst)
		}

		findex := strings.Index(logstringbufferst,badmessage)
		if findex != -1 {
			if debugmode{
				fmt.Println("Findmarker index", findex)
				fmt.Println("Bad user message flag", len(badmessage))
			}

			istring := logstringbufferst[findex+len(badmessage):]
			list1 := strings.Split(istring, separator)
			if debugmode{
				fmt.Println(list1)
			}

			username := ""
			srcip := ""
			callingstationid := ""
			for _, str := range list1 {
				vp := strings.Split(str, ":")
				ts := strings.TrimSpace(vp[0])
				switch ts {
				case "Username":
					username = vp[1];
					break
				case "Packet from IP":
					srcip = vp[1];
					break
				case "Calling station ID":
					callingstationid = vp[1];
					break
				default:
					break
				}
			}
			mmymutex.Lock()
			*mapp = append(*mapp, WrongAuth{username, srcip, callingstationid})
			mmymutex.Unlock()
			runtime.Gosched()
		}
	}
}

func JsHandler2(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		mmymutex.Lock()
		j, _ := json.Marshal(BadUsersl)
		BadUsersl.BadUsers = nil
		mmymutex.Unlock()
		runtime.Gosched()
		w.Write(j)


	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "No method")
	}
}

const JsonFileName = "params.json"

func main() {
	BadUsersl.BadUsers = make([]WrongAuth,0)
	var JParams params
	// Открываем файл с настройками
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	jSettingsFile, err := os.Open(exPath+"/"+JsonFileName)
	// Проверяем на ошибки
	if err != nil {
		fmt.Println("Ошибка:",err)
	}
	defer jSettingsFile.Close()

	FData, err := ioutil.ReadAll(jSettingsFile)
	if err != nil {
		fmt.Println("Ошибка:",err)
	}
	json.Unmarshal(FData,&JParams)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	if JParams.Debugmode == 1{
		debugmode = true
		fmt.Println("Enabled debugg mode")
	}else {
		fmt.Println("Disabled debugg mode")
	}

	go waitfsevent(watcher,JParams.Filename)

	err = watcher.Watch(JParams.Filename)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/radiuslog", JsHandler)
	http.HandleFunc("/badusers", JsHandler2)
	url1 := JParams.Ipaddrandport
	log.Println("StartJsonServer at",url1)
	http.ListenAndServe(url1, nil)

	watcher.Close()
}
