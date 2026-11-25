package api

import (
	"net/http"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/store"
)

// RouteClass is a main-mux route's trust level (spec §7.5).
type RouteClass string

const (
	// ClassPublic needs no authentication.
	ClassPublic RouteClass = "public"
	// ClassMachine is authenticated by its own credential (signed token, bearer secret).
	ClassMachine RouteClass = "machine"
	// ClassPending accepts a pending or active session; the handler authenticates.
	ClassPending RouteClass = "pending"
	// ClassSession needs an active session, and a recent step-up when Fresh is set.
	ClassSession RouteClass = "session"
)

// Route is one registered main-mux route.
type Route struct {
	Class   RouteClass
	Pattern string
	// Fresh is how recent the session's step-up must be; zero means no window.
	Fresh time.Duration
	// Detached counts the request for WaitDetached from before authentication (tracked).
	Detached bool
}

// routeOpt sets an optional property of a route.
type routeOpt func(*Route)

// fresh requires a session step-up within d (session routes only).
func fresh(d time.Duration) routeOpt { return func(r *Route) { r.Fresh = d } }

// detached marks a route whose handler keeps writing after its connection is gone.
func detached() routeOpt { return func(r *Route) { r.Detached = true } }

// StepupWindow is the freshness window for policy drafts, broker, pairing and backup actions
// (spec §7.3 rule 6).
const StepupWindow = 5 * time.Minute

// route is the only way onto the main mux: every route has a class, and session routes get
// the active-session and step-up middleware here. TestEveryRouteIsClassified enforces it.
func (s *Server) route(class RouteClass, pattern string, h http.Handler, opts ...routeOpt) {
	r := Route{Class: class, Pattern: pattern}
	for _, o := range opts {
		o(&r)
	}
	switch class {
	case ClassPublic, ClassMachine, ClassPending:
		if r.Fresh != 0 {
			panic("api: only session routes have a step-up window: " + pattern)
		}
	case ClassSession:
		h = s.activeSession(h, r.Fresh)
	default:
		panic("api: route without a valid class: " + pattern)
	}
	if r.Detached {
		h = s.tracked(h.ServeHTTP) // outermost: the count starts before the session lookup
	}
	s.registered = append(s.registered, r)
	s.mux.Handle(pattern, h)
}

// Routes lists every main-mux route with its class, in registration order.
func (s *Server) Routes() []Route { return append([]Route(nil), s.registered...) }

// activeSession admits only an active session (AuthenticateRequest refuses a pending one) whose
// last step-up is within fresh, when fresh is set.
func (s *Server) activeSession(h http.Handler, fresh time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sess, err := s.sessions.AuthenticateRequest(r)
		if err != nil {
			s.authFailed(w, err)
			return
		}
		if fresh > 0 && !steppedUpWithin(sess, fresh) {
			s.writeJSON(w, http.StatusForbidden, map[string]string{"error": "Confirm with your authenticator code first", "code": "stepup_stale"})
			return
		}
		h.ServeHTTP(w, r)
	})
}

func steppedUpWithin(sess *store.Session, d time.Duration) bool {
	return sess.StepupAt != nil && time.Since(*sess.StepupAt) <= d
}
