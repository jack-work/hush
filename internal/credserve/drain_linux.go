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

func (s *Server) ServeContext(ctx context.Context, listener net.Listener) error {
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
	serveErr := server.Serve(listener)
	cancel()
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
