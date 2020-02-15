package cls

import "fmt"

const (
	timeLayout = "2006-01-02 15:04:05"
)

var (
	errIncompressible = fmt.Errorf("the data is incompressible")
)
