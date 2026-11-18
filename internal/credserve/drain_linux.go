package credserve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

func (s *Server) connectionState(conn net.Conn, state http.ConnState) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if state == http.StateNew && !s.conns[conn] {
		s.conns[conn] = true
		s.connections.Add(1)
	}
	if (state == http.StateClosed || state == http.StateHijacked) && s.conns[conn] {
		delete(s.conns, conn)
		s.connections.Done()
	}
}

// ServeContext serves every listener until ctx ends, then drains. The
// first listener to fail stops them all.
func (s *Server) ServeContext(ctx context.Context, listeners ...net.Listener) error {
	if len(listeners) == 0 {
		return errors.New("credential server: no listener")
	}
	server := s.HTTPServer()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	shutdown := make(chan error, 1)
	go func() {
		<-ctx.Done()
		deadline, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		err := server.Shutdown(deadline)
		if err != nil {
			server.Close()
		}
		shutdown <- err
	}()
	served := make(chan error, len(listeners))
	for _, ln := range listeners {
		go func(ln net.Listener) { served <- server.Serve(ln) }(ln)
	}
	serveErr := <-served
	cancel()
	for range listeners[1:] {
		if err := <-served; serveErr == nil || errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = err
		}
	}
	drainErr := s.mgr.Stop()
	shutdownErr := <-shutdown
	s.connections.Wait()
	if drainErr != nil {
		return drainErr
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.New("credential listener failed")
	}
	if shutdownErr != nil {
		return errors.New("credential HTTP shutdown required connection closure")
	}
	return nil
}
