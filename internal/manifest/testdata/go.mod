module example.com/demo

go 1.23

toolchain go1.23.4

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/mod v0.0.0-20240101000000-000000000000 // indirect
	golang.org/x/text v0.14.0 // indirect
)

exclude github.com/old/pkg v0.1.0

replace github.com/broken/pkg => github.com/fixed/pkg v1.2.3
