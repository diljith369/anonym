# TORConnector - Framework for making requests to web resouces through TOR and can be used to initiate port scanning using nmap through TOR . Helps to analyse phishing pages , it gives back HTML source code along with the UI and anonymous port scanning.

## Getting Started

##### git clone https://github.com/diljithishere/TORConnector.git
##### go get golang.org/x/net/proxy
##### github.com/beevik/etree

##### Make sure that TOR is running in your machine

##### Set TOR as Windows Service
###### Download TOR browser bundle , move to the folder \Tor Browser\Browser\TorBrowser\Tor using command prompt as admin
###### Supply the following command 
###### tor.exe -service install 
###### Above command will install TOR as windows service (You may need to change the persmission of the service to make it run)

####  Debian /Ubuntu 
##### apt-get install tor
##### servie tor start

### Build exe 
#### go build Connector.go 
#### Run the exe 
#### On your favourite browser go to http://127.0.0.1:7777

### Prerequisites
#### Go 
#### nmap and TOR

### Built With
#### Go 

### Author
#### * **Diljith S** - *Initial work* - (https://github.com/diljithishere)