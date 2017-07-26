This ssh package contains helpers for working with ssh in go.  The `client.go` file
is a modified version of `docker/machine/libmachine/ssh/client.go` that only
uses golang's native ssh client. It has also been improved to resize the tty as
needed. The key functions are meant to be used by either client or server
and will generate/store keys if not found.

## Usage:

```go
package main

import (
	"github.com/Mester19/ssh-1"
)

func main() {
  session, err := ssh.NewNativeClient("username", "hostname.com:22", nil, nil)
  if err != nil {
    panic(err)
  }

  err = session.Shell()
  if err != nil {
    panic(err)
  }
}
```
