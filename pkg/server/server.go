package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"cmit/paas/warp/internal/comm"
	"cmit/paas/warp/internal/intf"
	"cmit/paas/warp/pkg/balancer"
	"cmit/paas/warp/pkg/config"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	api "cmit/paas/warp/api"

	"github.com/pkg/errors"
)

type server struct {
	*api.UnimplementedWarpApiServer
	grpcServer *grpc.Server
	b          *balancer.Balancer
	c          *config.ConfigSet
	port       uint16
	kaClose    chan struct{}
	kaLock     sync.Mutex
}

func NewAPIServer(g *grpc.Server, c *config.ConfigSet, port uint16) (*server, error) {
	grpc.EnableTracing = false
	b, err := balancer.NewBalancer(c)
	if err != nil {
		log.Errorf("create load balancer failed: %v", err)
		return nil, err
	}
	s := &server{
		grpcServer: g,
		b:          b,
		c:          c,
		port:       port,
	}
	api.RegisterWarpApiServer(g, s)
	return s, nil
}

func (s *server) Serve() error {
	address := fmt.Sprintf(":%d", s.port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Warn("listen failed")
		return err
	}

	s.kaClose = make(chan struct{})

	go func(listener net.Listener) {
		e := s.grpcServer.Serve(listener)
		log.Warnf("accept failed: %v", e)
	}(listener)
	return nil
}

func (s *server) Stop() {
	close(s.kaClose)
	s.grpcServer.Stop()
	s.b.Release()
}

func (s *server) Attach(c context.Context, r *api.AttachRequest) (*api.Empty, error) {
	var (
		err error
	)

	switch r.Type {
	case api.ServiceType_NAT:
		err = s.b.AttachNat(r.Ip)
	case api.ServiceType_FNAT:
		err = s.b.AttachFNat(r.Ip)
	default:
		err = errors.New("invalid service type")
	}

	if err != nil {
		log.Errorf("attach [%s] failed: %v", r.Ip, err)

	} else {
		log.Infof("attach [%s] success", r.Ip)
	}
	return &api.Empty{}, err
}

func (s *server) Detach(c context.Context, r *api.AttachRequest) (*api.Empty, error) {
	var (
		err error
	)

	switch r.Type {
	case api.ServiceType_NAT:
		err = s.b.DetachNat(r.Ip)
	case api.ServiceType_FNAT:
		err = s.b.DetachFNat(r.Ip)
	default:
		err = errors.New("invalid service type")
	}

	if err != nil {
		log.Errorf("detach [%s] failed: %v", r.Ip, err)

	} else {
		log.Infof("detach [%s] success", r.Ip)
	}
	return &api.Empty{}, err
}

func (s *server) AddService(c context.Context, r *api.AddRequest) (*api.Empty, error) {
	var (
		err error
		k   *comm.SrvKey
		v   *comm.SrvVal
	)

	for {
		if k, err = convertToSrvKey(r.Key); err != nil {
			break
		}
		if v, err = convertToSrvVal(k.IP, k.ParentIP, k.Proto, r.Val); err != nil {
			break
		}
		switch r.Type {
		case api.ServiceType_NAT:
			err = s.b.AddNat(k, v)
		case api.ServiceType_FNAT:
			err = s.b.AddFNat(k, v)
		default:
			err = errors.New("invalid service type")
		}
		break
	}
	if err != nil {
		log.Errorf("add service [%s:%d] failed: %v", r.Key.Ip, r.Key.Port, err)
		return nil, err
	}
	log.Infof("add service [%s:%d] success", r.Key.Ip, r.Key.Port)
	return &api.Empty{}, nil
}

func (s *server) DelService(c context.Context, r *api.DelRequest) (*api.Empty, error) {
	var (
		err error
		k   *comm.SrvKey
	)

	if k, err = convertToSrvKey(r.Key); err != nil {
		log.Errorf("delete service [%s:%d] failed: %v", r.Key.Ip, r.Key.Port, err)
		return nil, err
	}
	switch r.Type {
	case api.ServiceType_NAT:
		err = s.b.DelNat(k)
	case api.ServiceType_FNAT:
		err = s.b.DelFNat(k)
	default:
		err = errors.New("invalid service type")
	}
	if err != nil {
		log.Errorf("delete service [%s:%d] failed: %v", r.Key.Ip, r.Key.Port, err)
		return nil, err
	}
	log.Infof("delete service [%s:%d] success", r.Key.Ip, r.Key.Port)
	return &api.Empty{}, nil
}

func (s *server) GetService(c context.Context, r *api.Empty) (*api.GetResponse, error) {
	keys, vals := s.b.GetServices()
	resp := &api.GetResponse{Services: make([]*api.Service, 0, len(keys))}
	for i, k := range keys {
		resp.Services = append(resp.Services,
			&api.Service{
				Key: &api.ServiceKey{
					Ip:       strings.TrimRight(strings.Join([]string{k.IP, k.ParentIP}, "/"), "/"),
					Port:     uint32(k.Port),
					Protocol: api.Protocol(k.Proto),
				},
				Val: &api.ServiceAttr{
					LocalIp:       vals[i].LocalIP,
					RealPort:      uint32(vals[i].RealPort),
					RealServerIps: vals[i].RealServerIPs,
				},
			})
	}
	return resp, nil
}

func (s *server) Save(c context.Context, r *api.SaveReq) (*api.Empty, error) {
	/*
		if err := s.c.Save(r.FilePath); err != nil {
			return nil, err
		}
	*/
	return &api.Empty{}, nil
}

func (s *server) Poll(c context.Context, r *api.PollRequest) (*api.PollResponse, error) {
	var (
		natSes  []*comm.Session
		fnatSes []*comm.Session
	)
	resp := &api.PollResponse{TransportGroup: s.c.Global.Group}
	switch r.Type {
	case api.ServiceType_DEFAULT:
		// only keep local session
		natSes, _ = s.b.PollNatSesssion()
		resp.NatSessions = convertToAPISession(natSes, true)
		fnatSes, _ = s.b.PollFNatSesssion()
		resp.FnatSessions = convertToAPISession(fnatSes, true)
	case api.ServiceType_NAT:
		natSes, _ = s.b.PollNatSesssion()
		resp.NatSessions = convertToAPISession(natSes, false)
	case api.ServiceType_FNAT:
		fnatSes, _ = s.b.PollFNatSesssion()
		resp.FnatSessions = convertToAPISession(fnatSes, false)
	default:
		return nil, errors.New("invalid service type")
	}
	return resp, nil
}

func (s *server) Push(c context.Context, r *api.PushRequest) (*api.Empty, error) {
	if r.TransportGroup != s.c.Global.Group {
		return nil, errors.New("group mismatch")
	}
	natSes := convertToSession(r.NatSessions)
	fnatSes := convertToSession(r.FnatSessions)
	s.b.PushNatSession(natSes)
	s.b.PushFNatSession(fnatSes)
	return &api.Empty{}, nil
}

func (s *server) GetAttachedAddr(c context.Context, r *api.Empty) (*api.GetAttachedAddrResponse, error) {
	log.Info("get attached addr request")
	return &api.GetAttachedAddrResponse{Addrs: s.c.FNat.Attached}, nil
}

func (s *server) KeepAlive(r *api.KeepAliveRequest, stream api.WarpApi_KeepAliveServer) error {
	if !s.kaLock.TryLock() {
		return errors.New("existing keepalive session")
	}
	defer s.kaLock.Unlock()

	t := time.NewTicker(time.Duration(r.IntervalSec) * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.kaClose:
			return nil
		case <-t.C:
			uptime, err := comm.GetUptime()
			if err != nil {
				uptime = 0
			}
			if err = stream.Send(&api.KeepAliveResponse{UptimeSec: uptime}); err != nil {
				return err
			}
		}
	}
}

func convertToSrvKey(key *api.ServiceKey) (*comm.SrvKey, error) {
	k := &comm.SrvKey{
		Port:  uint16(key.Port),
		Proto: comm.SockProto(key.Protocol),
	}
	k.IP, k.ParentIP = comm.SplitIP(key.Ip)
	if !k.Proto.Valid() {
		return nil, errors.New("invalid protocol")
	}
	return k, nil
}

func convertToSrvVal(vip, pvip string, proto comm.SockProto, val *api.ServiceAttr) (*comm.SrvVal, error) {
	if len(val.RealServerIps) == 0 {
		return nil, errors.New("real server is empty")
	}
	v := &comm.SrvVal{
		Proto:         proto,
		Mode:          comm.ModeNat,
		RealPort:      uint16(val.RealPort),
		RealServerIPs: val.RealServerIps,
	}
	v.LocalIP, v.ParentLocalIP = comm.SplitIP(val.LocalIp)

	var err error
	if len(pvip) == 0 {
		if v.VirtualIfIdx, err = intf.GetIfIdxByIp(vip); err != nil {
			return nil, errors.Wrapf(err, "get virtual ip(%s) interface index failed", vip)
		}
	} else {
		if v.VirtualIfIdx, err = intf.GetIfIdxByIp(pvip); err != nil {
			return nil, errors.Wrapf(err, "get parent virtual ip(%s) interface index failed", pvip)
		}
	}
	if len(v.ParentLocalIP) == 0 {
		if v.LocalIfIdx, err = intf.GetIfIdxByIp(v.LocalIP); err != nil {
			return nil, errors.Wrapf(err, "get local ip(%s) interface index failed", v.LocalIP)
		}
	} else {
		if v.LocalIfIdx, err = intf.GetIfIdxByIp(v.ParentLocalIP); err != nil {
			return nil, errors.Wrapf(err, "get parent local ip(%s) interface index failed", v.ParentLocalIP)
		}
	}
	return v, nil
}

func convertToAPISession(ses []*comm.Session, local bool) []*api.Session {
	se := make([]*api.Session, 0, len(ses))
	if local {
		for _, v := range ses {
			if v.IsLocal {
				se = append(se, v.ToAPI())
			}
		}
	} else {
		for _, v := range ses {
			se = append(se, v.ToAPI())
		}
	}
	return se
}

func convertToSession(apiSes []*api.Session) []*comm.Session {
	ses := make([]*comm.Session, 0, len(apiSes))
	for _, v := range apiSes {
		se := comm.GetSession()
		se.FromAPI(v)
		ses = append(ses, se)
	}
	return ses
}
