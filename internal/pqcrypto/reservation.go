package pqcrypto

import "time"

// ReservationType is the domain type of a signed enrollment reservation request.
const ReservationType = "enroll_reservation"

// ReservationMaxSkew bounds how old or early a reservation request may be.
const ReservationMaxSkew = 5 * time.Minute

// EnrollReservation is the client's request to reserve an enrollment, signed by an active key
// of an enroller. It authorizes nothing at the broker; it keeps anyone who is not an
// enroller from holding the account's lock (§4.5 step 1).
type EnrollReservation struct {
	DeploymentID UUID      `json:"deployment_id"`
	AccountID    UUID      `json:"account_id"`
	RequestID    UUID      `json:"request_id"`
	PrincipalID  UUID      `json:"principal_id"`
	IssuedAt     Time      `json:"issued_at"`
	SigKeyID     HexID     `json:"sig_key_id"`
	Sig          HybridSig `json:"sig"`
}

// Digest is D over every field but the signature.
func (r *EnrollReservation) Digest() (Digest, error) {
	c := *r
	c.SigKeyID, c.Sig = "", HybridSig{}
	return D(ReservationType, struct {
		DeploymentID UUID `json:"deployment_id"`
		AccountID    UUID `json:"account_id"`
		RequestID    UUID `json:"request_id"`
		PrincipalID  UUID `json:"principal_id"`
		IssuedAt     Time `json:"issued_at"`
	}{c.DeploymentID, c.AccountID, c.RequestID, c.PrincipalID, c.IssuedAt})
}
