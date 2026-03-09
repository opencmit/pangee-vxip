package bpf

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"cmit/paas/warp/internal/comm"
	"cmit/paas/warp/internal/intf"
	"cmit/paas/warp/pkg/config"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type fnatElf struct {
	XdpProg       *ebpf.Program `ebpf:"warp_xdp_fnat"`
	TcProg        *ebpf.Program `ebpf:"warp_tc_fnat"`
	Service       *ebpf.Map     `ebpf:"warp_map_fnat_service"`
	InRealService *ebpf.Map     `ebpf:"warp_map_in_real_server"`
	RealServer    *ebpf.Map     `ebpf:"warp_map_fnat_real_server"`
	Connection    *ebpf.Map     `ebpf:"warp_map_fnat_connection"`
	InPort        *ebpf.Map     `ebpf:"warp_map_in_port"`
	Port          *ebpf.Map     `ebpf:"warp_map_fnat_port"`
	ReleasePort   *ebpf.Map     `ebpf:"warp_map_fnat_release_port"`
	Event         *ebpf.Map     `ebpf:"warp_map_fnat_event"`
	FailReason    *ebpf.Map     `ebpf:"warp_map_fail_event"`
}

type fnat struct {
	elf              fnatElf
	collection       *ebpf.CollectionSpec
	inRealServerSpec *ebpf.MapSpec
	inRealServer     sync.Map
	inPortSpec       *ebpf.MapSpec
	inPort           sync.Map
	foreignConn      sync.Map
	ifIdx            sync.Map
	portPoolSz       uint32
	ticker           *time.Ticker
	rd               *perf.Reader
	frd              *perf.Reader
	close            chan struct{}
	exclusive        bool
	timeout          uint32
	useXDP           bool
	minPort          uint32
	maxPort          uint32
}

func NewFNAT(gcfg *config.Global, fnatCfg *config.Balancer) (comm.Service, error) {
	s := &fnat{timeout: gcfg.ConnTimeout, exclusive: fnatCfg.ExclusivePortEnabled, useXDP: fnatCfg.UseXdp,
		minPort: gcfg.AvailablePortRange.Min, maxPort: gcfg.AvailablePortRange.Max}
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Errorf("remove mem lock failed: %v", err)
		return nil, err
	}

	if s.collection, err = ebpf.LoadCollectionSpec(gcfg.FNatFilePath); err != nil {
		log.Errorf("load collection spec failed: %v", err)
		return nil, err
	}
	_, ok := s.collection.Maps[fnatRealServerMapName]
	if !ok {
		log.Errorf("get spec failed: map object[%s] missing", fnatRealServerMapName)
		return nil, fmt.Errorf("%s object missing", fnatRealServerMapName)
	}
	if s.inRealServerSpec, ok = s.collection.Maps[inRealServerMapName]; !ok {
		log.Errorf("get spec failed: map object[%s] missing", inRealServerMapName)
		return nil, fmt.Errorf("%s object missing", inRealServerMapName)
	}
	if _, ok := s.collection.Maps[fnatPortMapName]; !ok {
		log.Errorf("get spec failed: map object[%s] missing", fnatPortMapName)
		return nil, fmt.Errorf("%s object missing", fnatPortMapName)
	}
	if s.inPortSpec, ok = s.collection.Maps[inPortMapName]; !ok {
		log.Errorf("get spec failed: map object[%s] missing", inPortMapName)
		return nil, fmt.Errorf("%s object missing", inPortMapName)
	}

	s.collection.Maps[fnatRealServerMapName].InnerMap = s.collection.Maps[inRealServerMapName]
	s.collection.Maps[fnatRealServerMapName].Extra = nil
	s.collection.Maps[fnatPortMapName].InnerMap = s.collection.Maps[inPortMapName]
	s.collection.Maps[fnatPortMapName].Extra = nil

	if err = s.collection.LoadAndAssign(&s.elf, nil); err != nil {
		log.Errorf("load and assign bpf objects failed: %v", err)
		return nil, err
	}

	if s.rd, err = perf.NewReader(s.elf.Event, os.Getpagesize()); err != nil {
		log.Errorf("create perf reader failed: %v", err)
		return nil, err
	}

	if s.frd, err = perf.NewReader(s.elf.FailReason, os.Getpagesize()); err != nil {
		log.Errorf("create fail perf reader failed: %v", err)
		return nil, err
	}

	log.Infof("services: %+v", s.elf.Service)
	log.Infof("real servers: %+v", s.elf.RealServer)
	log.Infof("connections: %+v", s.elf.Connection)
	if err = s.initPortMap(); err != nil {
		s.deinitPortMap()
		log.Errorf("init port map failed: %v", err)
		return nil, err
	}

	s.close = make(chan struct{})
	s.ticker = time.NewTicker(comm.TickerTimeSec)
	go s.recycle()
	go procEvent(s.rd)
	go s.procEvent()
	return s, nil
}

func (s *fnat) Release() {
	s.rd.Close()
	s.frd.Close()
	close(s.close)
	s.elf.XdpProg.Close()
	s.elf.TcProg.Close()
	s.elf.Service.Close()
	s.elf.Connection.Close()
	s.inRealServer.Range(func(k, v interface{}) bool {
		v.(*ebpf.Map).Close()
		return true
	})
	s.elf.RealServer.Close()
	s.elf.InRealService.Close()
	s.deinitPortMap()
	s.elf.Port.Close()
	s.elf.InPort.Close()
	s.elf.Event.Close()
}

func (s *fnat) Add(key *comm.SrvKey, val *comm.SrvVal) error {
	k, err := key.Marshal()
	if err != nil {
		return errors.Wrap(err, "marshal fnat key failed")
	}
	log.Infof("add fnat key: %v", k)
	val.MinPort, val.MaxPort = uint16(s.minPort), uint16(s.maxPort)
	v, err := val.Marshal()
	if err != nil {
		return errors.Wrap(err, "marshal fnat value failed")
	}

	inRsMap, err := createRealServerMap(s.inRealServerSpec, val)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			inRsMap.Close()
		}
	}()

	if err = s.elf.RealServer.Update(k, uint32(inRsMap.FD()), ebpf.UpdateNoExist); err != nil {
		return errors.Wrap(err, "put fnat inner map failed")
	}

	if err = s.elf.Service.Update(k, v, ebpf.UpdateNoExist); err != nil {
		s.elf.RealServer.Delete(k)
		return errors.Wrap(err, "put fnat service failed")
	}
	s.inRealServer.Store(*key, inRsMap)
	liteKey := *key
	liteKey.ParentIP = ""
	s.ifIdx.Store(liteKey, ifIdxInfo{uint32(val.VirtualIfIdx), uint32(val.LocalIfIdx)})
	return nil
}

func (s *fnat) Del(key *comm.SrvKey) error {
	k, err := key.Marshal()
	if err != nil {
		return errors.Wrap(err, "marshal fnat key failed")
	}
	log.Infof("del fnat key: %v", k)
	if err = s.elf.Service.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return errors.Wrap(err, "delete fnat service failed")
	}
	if err = s.elf.RealServer.Delete(k); err != nil {
		log.Errorf("del fnat[%v] inner map failed: %+v", key, err)
	}
	if m, ok := s.inRealServer.LoadAndDelete(*key); ok {
		m.(*ebpf.Map).Close()
	}
	liteKey := *key
	liteKey.ParentIP = ""
	s.ifIdx.Delete(liteKey)
	return nil
}

func (s *fnat) Attach(ip string) error {
	ifIdx, err := intf.GetIfIdxByIp(ip)
	if err != nil {
		return err
	}

	if s.useXDP {
		return comm.AttachLink(ifIdx, s.elf.XdpProg.FD())
	}
	return comm.AddFilter(ifIdx, s.elf.TcProg.FD())
}

func (s *fnat) Detach(ip string) error {
	ifIdx, err := intf.GetIfIdxByIp(ip)
	if err != nil {
		return err
	}

	if s.useXDP {
		return comm.DetachLink(ifIdx)
	}
	return comm.DelFilter(ifIdx)
}

// only keep positive connection
func (s *fnat) PollSession() []*comm.Session {
	conns := pollConn(s.elf.Connection)
	ses := make([]*comm.Session, 0, len(conns)/2)
	for k, v := range conns {
		delVal := v
		if v.IsPositive {
			se := comm.GetSession()
			se.FromConn(&k, v)
			ses = append(ses, se)
		}
		putConnVal(delVal)
	}
	return ses
}

func (s *fnat) PushSession(ses []*comm.Session) {
	ts, err := comm.GetUptime()
	if err != nil {
		log.Errorf("get up time failed: %v", err)
		return
	}
	ts *= comm.NsCnt
	for _, v := range ses {
		af, err := comm.GetAddrFamily(v.CIP)
		if err != nil {
			log.Errorf("get %s address family failed: %v", v.CIP, err)
			continue
		}

		idxes, ok := s.ifIdx.Load(comm.SrvKey{IP: v.VIP, Port: v.VPort, Proto: v.Proto})
		if !ok {
			log.Errorf("get %s:%d interface indexes failed", v.VIP, v.VPort)
			continue
		}
		indexes := idxes.(ifIdxInfo)
		ks, vs := v.ToConn(af, indexes.virtualIfIdx, indexes.localIfIdx, ts)
		pushConn(s.elf.Connection, &s.foreignConn, ks, vs)
		se := v
		comm.PutSession(se)
	}
}

func (s *fnat) recycle() {
	for {
		select {
		case <-s.close:
			return
		case <-s.ticker.C:
			ports := staleConn(s.elf.Connection, &s.foreignConn, uint64(s.timeout), s.exclusive)
			s.releasePorts(ports)
		}
	}
}

// exclusive port mode func below
func (s *fnat) initPortMap() error {
	if !s.exclusive {
		return nil
	}
	cpuNum := runtime.NumCPU()
	cnt := s.maxPort - s.minPort + 1
	s.portPoolSz = cnt / uint32(cpuNum)
	port := s.minPort
	for i := 0; i < cpuNum; i++ {
		m, err := ebpf.NewMap(s.inPortSpec)
		if err != nil {
			return errors.Wrap(err, "create port map failed")
		}
		for j := uint32(0); j < s.portPoolSz; j++ {
			m.Put(j, port)
			port++
		}
		m.Put(getIdx, uint32(0))
		m.Put(putIdx, uint32(0))
		m.Put(szIdx, uint32(s.portPoolSz))
		if err = s.elf.Port.Update(uint32(i), uint32(m.FD()), ebpf.UpdateNoExist); err != nil {
			m.Close()
			return errors.Wrap(err, "put fnat inner map failed")
		}
		s.inPort.Store(i, m)
	}
	log.Infof("cpu num is %d", cpuNum)
	return nil
}

func (s *fnat) deinitPortMap() {
	if !s.exclusive {
		return
	}
	s.inPort.Range(func(k, v interface{}) bool {
		v.(*ebpf.Map).Close()
		return true
	})
}

// release input and ebpf map together
func (s *fnat) releasePorts(ports []uint32) {
	var k, v uint32
	it := s.elf.ReleasePort.Iterate()
	for it.Next(&k, &v) {
		s.releasePort(k)
	}
	for _, p := range ports {
		s.releasePort(p)
	}
}

func (s *fnat) releasePort(port uint32) {
	cpu := uint32(port-s.minPort) / s.portPoolSz
	m, ok := s.inPort.Load(int(cpu))
	if !ok {
		return
	}
	var idx uint32
	if err := m.(*ebpf.Map).Lookup(putIdx, &idx); err != nil {
		log.Errorf("release port - get put-index failed: %v", err)
		return
	}
	if err := m.(*ebpf.Map).Put(idx, uint32(port)); err != nil {
		log.Errorf("release port - put port failed: %v", err)
		return
	}
	idx = (idx + 1) % uint32(s.portPoolSz)
	if err := m.(*ebpf.Map).Put(putIdx, idx); err != nil {
		log.Errorf("release port - put put-index failed: %v", err)
	}
}

func (s *fnat) procEvent() {
	for {
		record, err := s.frd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Errorf("reading from reader failed: %v", err)
			continue
		}
		if len(record.RawSample) < 4 {
			continue
		}
		code := comm.GetUint32(record.RawSample[:4])
		log.Errorf("redirect failed: %d", code)
	}
}
