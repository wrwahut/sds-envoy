package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretgrpc "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	gcplogger "github.com/envoyproxy/go-control-plane/pkg/log"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
	"net/http"
	"path"
	"strings"

	//"os"
	"sync"
	//"os"
	log "github.com/sirupsen/logrus"
)




type Callbacks struct {
	Signal   chan struct{}
	Debug    bool
	Fetches  int
	Requests int
	mu       sync.Mutex
}
func (cb *Callbacks) Report() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	log.WithFields(log.Fields{"fetches": cb.Fetches, "requests": cb.Requests}).Info("cb.Report()  callbacks")
}
func (cb *Callbacks) OnStreamOpen(_ context.Context, id int64, typ string) error {
	log.Infof("OnStreamOpen %d open for %s", id, typ)
	return nil
}
func (cb *Callbacks) OnStreamClosed(id int64) {
	log.Infof("OnStreamClosed %d closed", id)
}
func (cb *Callbacks) OnStreamRequest(id int64, r *discoverygrpc.DiscoveryRequest) error {
	//log.Infof("OnStreamRequest %v", r)
	log.Infof("OnStreamRequest %v", r.TypeUrl)
	//cb.mu.Lock()
	//defer cb.mu.Unlock()
	//cb.Requests++
	//if cb.Signal != nil {
	//	close(cb.Signal)
	//	cb.Signal = nil
	//}
	return nil
}
func (cb *Callbacks) OnStreamResponse(ctx context.Context, id int64, req *discoverygrpc.DiscoveryRequest,res *discoverygrpc.DiscoveryResponse) {
	log.Infof("OnStreamResponse...%v", res)
	cb.Report()
}
func (cb *Callbacks) OnFetchRequest(ctx context.Context, req *discoverygrpc.DiscoveryRequest) error {
	log.Infof("OnFetchRequest...", req)
	//cb.mu.Lock()
	//defer cb.mu.Unlock()
	//cb.Fetches++
	//if cb.Signal != nil {
	//	close(cb.Signal)
	//	cb.Signal = nil
	//}
	return nil
}
func (cb *Callbacks) OnFetchResponse(*discoverygrpc.DiscoveryRequest,*discoverygrpc.DiscoveryResponse) {
	log.Infof("OnFetchResponse...")
}

func (cb *Callbacks) OnDeltaStreamClosed(id int64) {

}

func (cb *Callbacks) OnDeltaStreamOpen(ctx context.Context, id int64, typ string) error {
	return nil
}

func (cb *Callbacks) OnStreamDeltaRequest(int64, *discoverygrpc.DeltaDiscoveryRequest) error{
	return nil
}
// OnStreamDelatResponse is called immediately prior to sending a response on a stream.
func (cb *Callbacks) OnStreamDeltaResponse(streamID int64, req *discoverygrpc.DeltaDiscoveryRequest, resp *discoverygrpc.DeltaDiscoveryResponse) {

}


type httpServer interface {
	serverhttp(req *http.Request)([]byte, int, error)
}

type HTTPGateway struct {
	// Log is an optional log for errors in response write
	Log gcplogger.Logger
	server serverv3.Server
	Gateway serverv3.HTTPGateway
}

func(h *HTTPGateway) serverhttp(req *http.Request) ([]byte, int, error){
	if req.Host == "" {
		return h.Gateway.ServeHTTP(req)
	}
	port := strings.Split(req.Host, ":")
	switch port[1] {
	case "9005":
		return h.ServeHTTP1(req)
	case "9004":
		return h.Gateway.ServeHTTP(req)
	}
	return []byte("ok!"), 200, nil
}

type request struct {
	TlsName string  `json:"tlsName"`
	CertContent string `json:"certContent"`
	KeyContent  string `json:"keyContent"`
}

func (h *HTTPGateway) ServeHTTP1(req *http.Request) ([]byte, int, error) {
	p := path.Clean(req.URL.Path)
	fmt.Println("----------------------------",p)
	fmt.Println(req.Body)
	if req.Body == nil {
		return nil, http.StatusBadRequest, fmt.Errorf("empty body")
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("cannot read body")
	}

	// parse as JSON
	//out := &discoverygrpc.DiscoveryRequest{}
	//err = protojson.Unmarshal(body, out)
	//if err != nil {
	//	return nil, http.StatusBadRequest, fmt.Errorf("cannot parse JSON body: " + err.Error())
	//}
	req_test := &request{}
	err = json.Unmarshal(body, req_test)
	if err != nil{

	}

	var secrets []types.Resource
	if snapshot, exists := cache.GetSnapshot("test-id"); exists == nil {
		resources := snapshot.GetResources(resource.SecretType)
		if _, ok := resources[req_test.TlsName]; ok {
			fmt.Printf("------------------")
			delete(resources, req_test.TlsName)
		}
		for _, secret := range resources{
			secrets = append(secrets, secret)
		}
	}
	if p == "/addTlsCertificate" {
		for _, s := range AddTlsCertificate(req_test.TlsName, req_test.CertContent, req_test.KeyContent){
			secrets = append(secrets, s)
		}
	}else if p == "/addValite"{
		for _, s := range AddValidationContext(req_test.TlsName, req_test.CertContent){
			secrets = append(secrets, s)
		}
	}else{
		return []byte("no endpoints"), 401, nil
	}

	setSnapshot(secrets)
	return []byte("👌!"), 200, nil
}

func (h *HTTPGateway) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	fmt.Println("============",req.Host, req)
	bytes, code, err := h.serverhttp(req)

	if err != nil {
		http.Error(resp, err.Error(), code)
		return
	}

	if bytes == nil {
		resp.WriteHeader(http.StatusNotModified)
		return
	}

	if _, err = resp.Write(bytes); err != nil && h.Log != nil {
		h.Log.Errorf("gateway error: %v", err)
	}
}

type Server struct {
	cb *Callbacks
	cache cachev3.SnapshotCache
	server serverv3.Server
}

var cache  = cachev3.NewSnapshotCache(false, cachev3.IDHash{}, nil)

//func init(){
//	cache = cachev3.NewSnapshotCache(true, cachev3.IDHash{}, nil)
//}


func NewServer(ctx context.Context) *Server{
	signal := make(chan struct{})
	cb := &Callbacks{
		Signal:   signal,
		Fetches:  0,
		Requests: 0,
	}
	//cache := cachev3.NewSnapshotCache(true, cachev3.IDHash{}, nil)
	srv := serverv3.NewServer(ctx, cache, cb)
	return &Server{
		cb: cb,
		cache: cache,
		server: srv,
	}
}

func(server *Server) start(ctx context.Context){
	go RunManagementServer(ctx, server.server,9003)
	go RunManagementGateway(server.server,9004)
	go RunManagementHttp(server.server,9005)
	<-server.cb.Signal

}

func RunManagementServer(ctx context.Context, server serverv3.Server, port uint) {
	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions, grpc.MaxConcurrentStreams(1000000))
	grpcServer := grpc.NewServer(grpcOptions...)

	addr, err := net.ResolveUnixAddr("unix", "/etc/envoy/sds/sds.sock")
	if err != nil {

	}

	lis, err := net.ListenUnix("unix", addr)

	//lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.WithError(err).Fatal("failed to listen")
	}
	// register services
	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	// NOT used since we run ADS
	secretgrpc.RegisterSecretDiscoveryServiceServer(grpcServer, server)
	//endpointservice.RegisterEndpointDiscoveryServiceServer(grpcServer, server)
	// clusterservice.RegisterClusterDiscoveryServiceServer(grpcServer, server)
	// routeservice.RegisterRouteDiscoveryServiceServer(grpcServer, server)
	// listenerservice.RegisterListenerDiscoveryServiceServer(grpcServer, server)
	log.WithFields(log.Fields{"port": port}).Info("management server listening")
	go func() {
		if err = grpcServer.Serve(lis); err != nil {
			log.Error(err)
		}
	}()
	<-ctx.Done()
	grpcServer.GracefulStop()
}

func RunManagementGateway(srv serverv3.Server, port uint) {
	log.Println("gateway listening HTTP/1.1 :", port)
	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: &HTTPGateway{Gateway: serverv3.HTTPGateway{Server: srv},}}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
}

func RunManagementHttp(srv serverv3.Server, port uint){
	log.Println("gateway listening HTTP/1.1 :", port)
	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: &HTTPGateway{server: srv}}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
}



func setSnapshot(secrets []types.Resource){
	//var secrets []types.Resource
	//for _, s := range resources {
	//	secrets = append(secrets, s)
	//}
	snapshot, _ := cachev3.NewSnapshot("1.0", map[resource.Type][]types.Resource{
		resource.SecretType:          secrets,
	})
	err := cache.SetSnapshot(context.Background(), "test-id", snapshot)
	if err != nil {
		log.Printf("snapshot error %q for %+v\n", err, snapshot)
	}
}

func AddTlsCertificate(tlsName, certContent, keyContent string) []*auth.Secret{
	return []*auth.Secret{
		{
			Name: tlsName,
			Type: &auth.Secret_TlsCertificate{
				TlsCertificate: &auth.TlsCertificate{
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(decode(keyContent))},
					},
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(decode(certContent))},
					},
				},
			},
		},
	}
}

func AddValidationContext(caName, certContent string) []*auth.Secret{
	return []*auth.Secret{
		{
			Name: caName,
			Type: &auth.Secret_ValidationContext{
				ValidationContext: &auth.CertificateValidationContext{
					TrustedCa: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: []byte(decode(certContent))},
					},
				},
			},
		},
	}
}

func decode(encoded string) string{
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	fmt.Println("============docode=>", string(decoded))
	return string(decoded)
}