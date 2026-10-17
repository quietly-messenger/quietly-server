module github.com/quietly-messenger/quietly-server

go 1.26.5

require (
	github.com/go-chi/chi/v5 v5.5.0
	github.com/gorilla/websocket v1.5.3
	github.com/jackc/pgx/v5 v5.11.0
	github.com/quietly-messenger/quietly-crypto v0.0.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/quietly-messenger/quietly-crypto => ../quietly-crypto
