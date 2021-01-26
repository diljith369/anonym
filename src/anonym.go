package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/gocolly/colly"
	"github.com/gocolly/colly/proxy"
	"github.com/gorilla/mux"
)

type Port struct {
	Protocol       string
	PortID         string
	State          string
	Reason         string
	ServiceName    string
	ProductName    string
	ProductVersion string
	ExtraInfo      string
	OSType         string
}
type Host struct {
	TorResponse string
	Address     string
	HostName    string
	Ports       []Port
}

var (
	anonymtempl, scantempl, torinteltempl *template.Template
	oHost                                 Host
	fName                                 string
	torclient                             *http.Client
	Links                                 []string
	allurls                               []string
)

func portscan(target string, finflag chan string) {
	nmapPath, err := exec.LookPath("nmap")
	if err == nil {
		torproxy := "socks4://127.0.0.1:9050"
		scannerargs := []string{"--proxy", torproxy, "--dns-servers", "1.1.1.1", "-T4", "-sV", "-Pn", "-A", "--reason", "-v", target, "-oX", fName}
		//args2 := []string{"-Pn", "-sT", "-sV", "-O", target, "-oX", fName}
		scanner := exec.Command(nmapPath, scannerargs...)
		err := scanner.Start()
		//fmt.Println(string(output))
		fmt.Println("scan started")
		if err != nil {
			fmt.Println(err)
			return
		}
		scanner.Wait()
	}
	finflag <- "Scanning is over"
}

func crawllinks(keyword string, finflag chan string) {
	//var getlink string
	torproxy := "socks5://127.0.0.1:9050"
	torurls := []string{`http://msydqstlz2kzerdg.onion/search/?q=RPL`,
		`http://3bbaaaccczcbdddz.onion/search?q=RPL`,
		`http://haystakvxad7wbk5.onion/?q=RPL`,
		`http://5u56fjmxu63xcmbk.onion/search.php?search=RPL&submit=Search&rt=`,
		`http://xmh57jrzrnw6insl.onion/4a1f6b371c/search.cgi?s=DRP&q=RPL&cmd=Search%21`}

	c := colly.NewCollector(

		colly.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"),
	)
	rp, err := proxy.RoundRobinProxySwitcher(torproxy)
	if err != nil {
		fmt.Println(err)
	}
	c.SetProxyFunc(rp)
	c.OnResponse(func(r *colly.Response) {
		resp := string(r.Body)
		//
		hrefs, _ := regexp.Compile(`<a\s+(?:[^>]*?\s+)?href=["\']([^"\']*)`)
		allhrefurls := hrefs.FindAllString(resp, -1)
		for i := 0; i < len(allhrefurls); i++ {
			allurls = append(allurls, allhrefurls[i])
		}

	})

	for i := 0; i < len(torurls); i++ {
		targetURL := strings.Replace(torurls[i], "RPL", keyword, -1)
		fmt.Println(targetURL)
		c.Visit(targetURL)
	}
	finflag <- "finished"
}

func findactuallinks() {
	actuallinks, _ := regexp.Compile(`(http):\/\/?(?:[a-z0-9\-\.]+)(?::[0-9]+)?(?:\/|\/(?:[\w#!:\.\?\+=&amp;%@!\-\/\(\)]+)|\?(?:[\w#!:\.\?\+=&amp;%@!\-\/\(\)]+))?$`)
	for i := 0; i < len(allurls); i++ {
		getlinks := actuallinks.FindAllString(allurls[i], -1)
		for _, val := range getlinks {
			Links = append(Links, val)
		}
	}
}

func init() {
	anonymtempl = template.Must(template.ParseFiles("template/anonym.html"))
	scantempl = template.Must(template.ParseFiles("template/scanner.html"))
	torinteltempl = template.Must(template.ParseFiles("template/torintel.html"))

	oHost = Host{}
	fName = "anonscanres2.xml"
}

func parseScanResult(filename string, finflag chan string) {
	doc := etree.NewDocument()
	err := doc.ReadFromFile(filename)
	if err != nil {
		fmt.Println(err)
	}

	root := doc.SelectElement("nmaprun")
	//fmt.Println(root.Tag)
	host := root.SelectElement("host")
	if host != nil {
		address := host.SelectElement("address")
		if address != nil && address.SelectAttr("addr") != nil {
			oHost.Address = address.SelectAttr("addr").Value
		}

		hostnames := host.SelectElement("hostnames")
		if len(hostnames.SelectElements("hostname")) > 0 {
			oHost.HostName = hostnames.SelectElements("hostname")[0].SelectAttr("name").Value

		}
		ports := host.SelectElement("ports")

		oHost.Ports = []Port{}
		for _, port := range ports.SelectElements("port") {
			oPort := Port{}
			if port.SelectAttr("protocol") != nil {
				oPort.Protocol = (port.SelectAttr("protocol").Value)
			}
			if port.SelectAttr("portid") != nil {
				oPort.PortID = (port.SelectAttr("portid").Value)
			}
			state := port.SelectElement("state")
			if state != nil {
				oPort.State = state.SelectAttr("state").Value
				oPort.Reason = state.SelectAttr("reason").Value
			}
			service := port.SelectElement("service")
			if service != nil {
				if service.SelectAttr("name") != nil {
					oPort.ServiceName = (service.SelectAttr("name").Value)
				}
				if service.SelectAttr("extrainfo") != nil {
					oPort.ExtraInfo = (service.SelectAttr("extrainfo").Value)
				}
				if service.SelectAttr("version") != nil {
					oPort.ProductVersion = (service.SelectAttr("version").Value)
				}
				if service.SelectAttr("product") != nil {
					oPort.ProductName = (service.SelectAttr("product").Value)
				}
			}

			oHost.Ports = append(oHost.Ports, oPort)

		}
	}

	finflag <- "Parsing over"
}

func anonymhomepage(httpw http.ResponseWriter, req *http.Request) {
	err := anonymtempl.Execute(httpw, nil)
	if err != nil {
		fmt.Println(err)
	}
}

func anonymhandleoptions(httpw http.ResponseWriter, req *http.Request) {

	err := req.ParseForm()
	if err != nil {
		fmt.Println(err)
	}
	userchoice := req.Form.Get("userchoice")
	if userchoice == "darkintel" {
		keyword := req.Form.Get("keyword")
		fmt.Println(userchoice)

		if strings.TrimSpace(keyword) != "" {
			fmt.Println(keyword)
			finflag := make(chan string)
			go crawllinks(keyword, finflag)
			<-finflag
			findactuallinks()
			err = torinteltempl.Execute(httpw, Links)
			if err != nil {
				fmt.Println(err)
			}
			Links = Links[:0]
			allurls = allurls[:0]
			close(finflag)
		}
	} else if userchoice == "tscanner" {
		target := req.Form.Get("target")
		if strings.TrimSpace(target) != "" {
			fmt.Println(target)
			finflag := make(chan string)
			go portscan(target, finflag)
			<-finflag
			go parseScanResult(fName, finflag)
			<-finflag
			err = scantempl.Execute(httpw, oHost)
			if err != nil {
				fmt.Println(err)
			}
			close(finflag)
		}

	}

}

func connectTor(targetURL string) string {

	//targeturl := ""
	var result string
	torproxy := "socks5://127.0.0.1:9050"
	c := colly.NewCollector(

		colly.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"),
	)
	rp, err := proxy.RoundRobinProxySwitcher(torproxy)
	if err != nil {
		fmt.Println(err)
	}
	c.SetProxyFunc(rp)
	c.OnResponse(func(r *colly.Response) {
		log.Println("response received", r.StatusCode)
		result = string(r.Body)
		fmt.Printf("got response")
	})
	fmt.Printf("visiting page")

	c.Visit(targetURL)
	return result
}

func main() {
	fmt.Println("App is ready : http://0.0.0.0:7777")
	router := mux.NewRouter()
	router.HandleFunc("/", anonymhomepage).Methods("GET")
	router.HandleFunc("/", anonymhandleoptions).Methods("POST")
	router.PathPrefix("/static/css/").Handler(http.StripPrefix("/static/css/", http.FileServer(http.Dir("static/css/"))))

	srv := &http.Server{
		Handler: router,
		Addr:    "0.0.0.0:7777",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 180 * time.Second,
		ReadTimeout:  180 * time.Second,
	}
	srv.ListenAndServe()
}
