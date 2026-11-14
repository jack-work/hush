package oauth

import "errors"

var ErrStopped = errors.New("oauth: manager is stopped")
var ErrDrainUncertain = errors.New("oauth: shutdown drained with unresolved credential state")

func (m *Manager) begin() error {
	m.lifeMu.Lock()
	defer m.lifeMu.Unlock()
	if m.stopping {
		return ErrStopped
	}
	m.work.Add(1)
	return nil
}
func (m *Manager) closing() bool { m.lifeMu.Lock(); defer m.lifeMu.Unlock(); return m.stopping }
func (m *Manager) uncertain()    { m.lifeMu.Lock(); m.drainUncertain = true; m.lifeMu.Unlock() }

func (m *Manager) Stop() error {
	m.lifeMu.Lock()
	if m.stopped == nil {
		m.stopped = make(chan struct{})
	}
	if m.stopping {
		done := m.stopped
		m.lifeMu.Unlock()
		<-done
		m.lifeMu.Lock()
		err := m.stopErr
		m.lifeMu.Unlock()
		return err
	}
	m.stopping = true
	if m.cancel != nil {
		m.cancel()
	}
	m.lifeMu.Unlock()
	m.work.Wait()
	m.mu.Lock()
	for _, st := range m.configs {
		st.tokens.Store(nil)
	}
	m.mu.Unlock()
	m.lifeMu.Lock()
	if m.drainUncertain {
		m.stopErr = ErrDrainUncertain
	}
	err := m.stopErr
	close(m.stopped)
	m.lifeMu.Unlock()
	return err
}

func (m *Manager) mintClient() (httpDoer, error) {
	m.lifeMu.Lock()
	defer m.lifeMu.Unlock()
	if m.stopping {
		return nil, ErrStopped
	}
	return m.httpClient, nil
}
