package oauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
)

type drainDoer struct {
	entered   chan struct{}
	cancelled chan struct{}
	release   chan struct{}
	posts     atomic.Int32
	status    int
	body      string
	failed    bool
}

func (d *drainDoer) Do(r *http.Request) (*http.Response, error) {
	d.posts.Add(1)
	close(d.entered)
	<-r.Context().Done()
	close(d.cancelled)
	<-d.release
	if d.failed {
		return nil, errors.New("FAKE_TRANSPORT_CANARY")
	}
	return &http.Response{StatusCode: d.status, Body: io.NopCloser(strings.NewReader(d.body))}, nil
}
func startDrainFixture(t *testing.T, mode string) (*Manager, *drainDoer, *bytes.Buffer, func()) {
	t.Helper()
	m := newTestManager(t, t.TempDir(), newTestKey(t))
	var logs bytes.Buffer
	m.logger = log.New(&logs, "", 0)
	if err := m.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatal(err)
	}
	st := m.lookup(testCfg.Name)
	old := *st.tokens.Load()
	old.prevRefresh = "R0"
	st.tokens.Store(&old)
	d := &drainDoer{entered: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{}), status: 200, body: `{"access_token":"A2","refresh_token":"R2","expires_in":3600}`}
	if mode == "transport" {
		d.failed = true
	}
	if mode == "permanent" {
		d.status = 400
		d.body = `{"error":"invalid_grant","error_description":"FAKE_ERROR_CANARY"}`
	}
	m.httpClient = d
	var once sync.Once
	release := func() { once.Do(func() { close(d.release) }) }
	t.Cleanup(release)
	return m, d, &logs, release
}
func assertStopPending(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("Stop returned before admitted work drained")
	default:
	}
}
func assertStoppedAPIs(t *testing.T, m *Manager) {
	t.Helper()
	for name, operation := range map[string]func() error{
		"start":       m.Start,
		"HTTP client": func() error { return m.SetHTTPClient(&http.Client{}) },
		"register": func() error {
			return m.Register(testCfg, Tokens{AccessToken: "FAKE_POST_STOP", RefreshToken: "FAKE_POST_STOP", ExpiresIn: 3600})
		},
		"adopt":        func() error { return m.Adopt(testCfg.Name) },
		"delete":       func() error { return m.Delete(testCfg.Name) },
		"refresh":      func() error { _, err := m.Refresh(testCfg.Name); return err },
		"get":          func() error { _, err := m.Get(testCfg.Name); return err },
		"lease":        func() error { _, err := m.Lease(testCfg.Name); return err },
		"full refresh": func() error { _, _, err := m.RefreshFull(testCfg.Name); return err },
	} {
		if err := operation(); !errors.Is(err, ErrStopped) || errors.Is(err, ErrRefreshPermanent) || errors.Is(err, ErrRefreshTransient) {
			t.Errorf("%s did not return distinct stopped state", name)
		}
	}
	if names, err := m.List(); !errors.Is(err, ErrStopped) || len(names) != 0 {
		t.Fatal("stopped manager listed credentials or claimed an empty clean list")
	}
}

func TestStopJoinsSuccessfulResponseAfterCancellationAndPreservesCommit(t *testing.T) {
	m, d, _, release := startDrainFixture(t, "success")
	refreshed := make(chan error, 1)
	go func() { _, err := m.Refresh(testCfg.Name); refreshed <- err }()
	<-d.entered
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	<-d.cancelled
	assertStopPending(t, stopped)
	assertStoppedAPIs(t, m)
	release()
	if err := <-refreshed; err != nil {
		t.Fatal("completed valid response was discarded")
	}
	if err := <-stopped; err != nil {
		t.Fatal("committed response reported unresolved")
	}
	_, disk, _, err := m.loadFile(m.filePath(testCfg.Name))
	if err != nil || disk.refresh != "R2" || disk.access != "A2" {
		t.Fatal("successor not durably committed before Stop returned")
	}
	if m.lookup(testCfg.Name).tokens.Load() != nil {
		t.Fatal("cache resurrected after Stop")
	}
	before, err := os.ReadFile(m.filePath(testCfg.Name))
	if err != nil {
		t.Fatal(err)
	}
	assertStoppedAPIs(t, m)
	after, err := os.ReadFile(m.filePath(testCfg.Name))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("post-Stop API changed persistent state")
	}
	if d.posts.Load() != 1 {
		t.Fatal("closing manager minted another credential")
	}
}

func TestConcurrentStopKeepsOneUncertainOutcomeAndNeverRetriesOrLatches(t *testing.T) {
	for _, mode := range []string{"transport", "permanent"} {
		t.Run(mode, func(t *testing.T) {
			m, d, logs, release := startDrainFixture(t, mode)
			refreshed := make(chan error, 1)
			go func() { _, err := m.Refresh(testCfg.Name); refreshed <- err }()
			<-d.entered
			results := make(chan error, 16)
			go func() { results <- m.Stop() }()
			<-d.cancelled
			for range 15 {
				go func() { results <- m.Stop() }()
			}
			assertStopPending(t, results)
			release()
			if err := <-refreshed; !errors.Is(err, ErrStopped) || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("cancelled refresh leaked or claimed re-login")
			}
			for range 16 {
				if err := <-results; err != ErrDrainUncertain {
					t.Fatal("concurrent Stop returned a different or false-clean outcome")
				}
			}
			if m.Stop() != ErrDrainUncertain {
				t.Fatal("repeated Stop lost uncertain outcome")
			}
			_, disk, _, err := m.loadFile(m.filePath(testCfg.Name))
			if err != nil || disk.refresh != "R1" || disk.relogin != "" {
				t.Fatal("shutdown manufactured a committed rotation or re-login mark")
			}
			if d.posts.Load() != 1 || strings.Contains(logs.String(), "CANARY") || strings.Contains(logs.String(), "retrying with the previous") {
				t.Fatal("shutdown retried or reflected provider error")
			}
		})
	}
}

func TestStopReportsFailedCommitWithoutPublishingSuccessor(t *testing.T) {
	m, d, _, release := startDrainFixture(t, "success")
	refreshed := make(chan error, 1)
	go func() { _, err := m.Refresh(testCfg.Name); refreshed <- err }()
	<-d.entered
	saved := m.oauthDir() + "-saved"
	if err := os.Rename(m.oauthDir(), saved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.oauthDir(), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	<-d.cancelled
	assertStopPending(t, stopped)
	release()
	if err := <-refreshed; err != ErrDrainUncertain {
		t.Fatal("failed persistence did not surface a fixed status")
	}
	if err := <-stopped; err != ErrDrainUncertain {
		t.Fatal("failed commit was called a clean drain")
	}
	_, disk, _, err := m.loadFile(filepath.Join(saved, testCfg.Name+".toml"))
	if err != nil || disk.refresh != "R1" {
		t.Fatal("failed commit replaced the last durable pair")
	}
	if m.lookup(testCfg.Name).tokens.Load() != nil {
		t.Fatal("failed successor survived stopped cache")
	}
}

func TestRealTLSPartialRotationResponseRemainsUncertain(t *testing.T) {
	entered, cancelled := make(chan struct{}), make(chan struct{})
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"FAKE_PARTIAL_CANARY`)
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer server.Close()
	m := newTestManager(t, t.TempDir(), newTestKey(t))
	cfg := testCfg
	cfg.TokenURL = server.URL
	m.SetHTTPClient(server.Client())
	if err := m.Register(cfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatal(err)
	}
	refreshed := make(chan error, 1)
	go func() { _, err := m.Refresh(cfg.Name); refreshed <- err }()
	<-entered
	if err := m.Stop(); err != ErrDrainUncertain {
		t.Fatal("lost response was declared clean")
	}
	<-cancelled
	if err := <-refreshed; !errors.Is(err, ErrStopped) || strings.Contains(err.Error(), "CANARY") {
		t.Fatal("partial response leaked or was treated as recovery")
	}
	if posts.Load() != 1 {
		t.Fatal("partial rotation was retried")
	}
	_, disk, _, err := m.loadFile(m.filePath(cfg.Name))
	if err != nil || disk.refresh != "R1" || disk.relogin != "" {
		t.Fatal("partial response manufactured successor or login requirement")
	}
}

type registrationBarrier struct{ entered, release chan struct{} }

func (registrationBarrier) Name() string          { return "drain-registration" }
func (registrationBarrier) MintsOnRegister() bool { return false }
func (g registrationBarrier) Validate(Config, Tokens) error {
	close(g.entered)
	<-g.release
	return nil
}
func (registrationBarrier) Mint(context.Context, httpDoer, Config, string) (Tokens, error) {
	return Tokens{}, errors.New("unexpected fake mint")
}

func TestStopJoinsAdmittedRegistration(t *testing.T) {
	g := registrationBarrier{make(chan struct{}), make(chan struct{})}
	registerGrant(g)
	defer delete(grants, g.Name())
	m := newTestManager(t, t.TempDir(), newTestKey(t))
	cfg := testCfg
	cfg.Grant = g.Name()
	registered := make(chan error, 1)
	go func() { registered <- m.Register(cfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}) }()
	<-g.entered
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	<-m.ctx.Done()
	assertStopPending(t, stopped)
	close(g.release)
	if err := <-registered; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	_, disk, _, err := m.loadFile(m.filePath(cfg.Name))
	if err != nil || disk.refresh != "R1" {
		t.Fatal("admitted complete registration was not committed")
	}
	assertStoppedAPIs(t, m)
}

type identityBarrier struct {
	inner            age.Identity
	entered, release chan struct{}
	once             sync.Once
}

func (i *identityBarrier) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	i.once.Do(func() { close(i.entered); <-i.release })
	return i.inner.Unwrap(stanzas)
}

func TestStopJoinsAdoptAndStartupWriters(t *testing.T) {
	for _, mode := range []string{"adopt", "start"} {
		t.Run(mode, func(t *testing.T) {
			dir, key := t.TempDir(), newTestKey(t)
			seed := newTestManager(t, dir, key)
			if err := seed.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
				t.Fatal(err)
			}
			if mode == "start" {
				st := seed.lookup(testCfg.Name)
				marked := *st.tokens.Load()
				marked.relogin = `token endpoint 400: {"error":"invalid_grant","echo":"FAKE_OLD_BODY"}`
				if err := seed.saveFile(st.cfg, marked); err != nil {
					t.Fatal(err)
				}
			}
			seed.Stop()
			barrier := &identityBarrier{inner: key, entered: make(chan struct{}), release: make(chan struct{})}
			m := NewManager(dir, []age.Identity{barrier}, key.Recipient(), log.New(io.Discard, "", 0))
			t.Cleanup(func() { m.Stop() })
			operation := make(chan error, 1)
			go func() {
				if mode == "start" {
					operation <- m.Start()
				} else {
					operation <- m.Adopt(testCfg.Name)
				}
			}()
			<-barrier.entered
			stopped := make(chan error, 1)
			go func() { stopped <- m.Stop() }()
			<-m.ctx.Done()
			assertStopPending(t, stopped)
			close(barrier.release)
			if err := <-operation; err != nil {
				t.Fatal(err)
			}
			if err := <-stopped; err != nil {
				t.Fatal(err)
			}
			if state := m.lookup(testCfg.Name); state != nil && state.tokens.Load() != nil {
				t.Fatal("adoption resurrected cache")
			}
			if mode == "start" {
				_, disk, _, err := m.loadFile(m.filePath(testCfg.Name))
				if err != nil || disk.relogin != "invalid_grant" {
					t.Fatal("startup rewrite not drained before return")
				}
			}
		})
	}
}

func TestStopJoinsAdmittedDelete(t *testing.T) {
	m := newTestManager(t, t.TempDir(), newTestKey(t))
	if err := m.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	m.removeFile = func(path string) error { close(entered); <-release; return os.Remove(path) }
	deleted := make(chan error, 1)
	go func() { deleted <- m.Delete(testCfg.Name) }()
	<-entered
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	<-m.ctx.Done()
	assertStopPending(t, stopped)
	close(release)
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.filePath(testCfg.Name)); !os.IsNotExist(err) {
		t.Fatal("delete was not complete before Stop")
	}
}

func TestStopJoinsProactiveLoopBeforeItCanAdmitRefresh(t *testing.T) {
	m := newTestManager(t, t.TempDir(), newTestKey(t))
	entered, release := make(chan struct{}), make(chan struct{})
	m.after = func(time.Duration) <-chan time.Time { close(entered); <-release; return make(chan time.Time) }
	if err := m.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatal(err)
	}
	<-entered
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	<-m.ctx.Done()
	assertStopPending(t, stopped)
	close(release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
}

func TestCoalescedRefreshWaitersFinishWhenStopClosesAdmission(t *testing.T) {
	m, d, _, release := startDrainFixture(t, "success")
	results := make(chan error, 33)
	go func() { _, err := m.Refresh(testCfg.Name); results <- err }()
	<-d.entered
	ready := make(chan struct{})
	for range 32 {
		go func() { ready <- struct{}{}; _, err := m.Refresh(testCfg.Name); results <- err }()
	}
	for range 32 {
		<-ready
	}
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	<-d.cancelled
	release()
	if err := <-stopped; err != nil {
		t.Fatal("successful coalesced commit not drained")
	}
	successes := 0
	for range 33 {
		err := <-results
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrStopped) {
			t.Fatal("coalesced waiter did not finish with a fixed outcome")
		}
	}
	if successes < 1 || d.posts.Load() != 1 {
		t.Fatal("coalesced calls replayed a rotation")
	}
}

func TestMismatchedAccountRotationIsNotAClaimedCleanDrain(t *testing.T) {
	m := newTestManager(t, t.TempDir(), newTestKey(t))
	cfg := chatGPTConfig()
	if err := m.Register(cfg, chatGPTSeed()); err != nil {
		t.Fatal(err)
	}
	raw := `{"access_token":"` + chatGPTJWT("other_account") + `","refresh_token":"FAKE_OTHER_ACCOUNT","expires_in":3600}`
	m.httpClient = fakeDoer{status: 200, body: raw}
	if _, err := m.Refresh(cfg.Name); err == nil {
		t.Fatal("mismatched successor accepted")
	}
	if m.Stop() != ErrDrainUncertain {
		t.Fatal("unpublished mismatched-account pair was called clean")
	}
	_, disk, _, err := m.loadFile(m.filePath(cfg.Name))
	if err != nil || disk.refresh == "FAKE_OTHER_ACCOUNT" {
		t.Fatal("mismatched pair published")
	}
}

func TestSyncRenameAndDirectoryFailuresStayUncertainWithoutPublication(t *testing.T) {
	for _, stage := range []string{"file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			m, d, _, release := startDrainFixture(t, "success")
			fault := errors.New("FAKE_IO_CANARY")
			switch stage {
			case "file-sync":
				m.syncFile = func(*os.File) error { return fault }
			case "rename":
				m.renameFile = func(string, string) error { return fault }
			case "directory-sync":
				m.syncDirectory = func(*os.File) error { return fault }
			}
			refreshed := make(chan error, 1)
			go func() { _, err := m.Refresh(testCfg.Name); refreshed <- err }()
			<-d.entered
			stopped := make(chan error, 1)
			go func() { stopped <- m.Stop() }()
			<-d.cancelled
			release()
			if err := <-refreshed; err != ErrDrainUncertain || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("commit failure was reflected or misclassified")
			}
			if err := <-stopped; err != ErrDrainUncertain {
				t.Fatal("failed durable phase reported clean")
			}
			if m.lookup(testCfg.Name).tokens.Load() != nil {
				t.Fatal("unconfirmed successor published after Stop")
			}
		})
	}
}

func TestStopCannotReturnBeforeSuccessfulDirectorySync(t *testing.T) {
	m, d, _, release := startDrainFixture(t, "success")
	entered, commit := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(commit) }) }
	t.Cleanup(unblock)
	m.syncDirectory = func(f *os.File) error { close(entered); <-commit; return f.Sync() }
	refreshed := make(chan error, 1)
	go func() { _, err := m.Refresh(testCfg.Name); refreshed <- err }()
	<-d.entered
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	<-d.cancelled
	release()
	<-entered
	assertStopPending(t, stopped)
	current := m.lookup(testCfg.Name).tokens.Load()
	if current == nil || current.access != "A1" || current.refresh != "R1" {
		t.Fatal("successor visible before directory sync")
	}
	unblock()
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	_, disk, _, err := m.loadFile(m.filePath(testCfg.Name))
	if err != nil || disk.refresh != "R2" {
		t.Fatal("completed durable successor lost")
	}
}
