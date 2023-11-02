package auth

import (
  "encoding/json"
  "io"
  "reflect"

  "github.com/golang/glog"
  "golang.org/x/net/websocket"
)

type PushCallback = func (*NotificationEvent) bool

type IPushEndpoint interface {
  io.Closer
  IsClosed() bool
  RegisterCallback(PushCallback)
  RemoveCallback(PushCallback)
  Push(*NotificationEvent)
  Write([]byte) error
}

type NotificationEvent struct {
  Command              string `json:"command"`
  Event                string `json:"event"`
  Message              string `json:"message"`
  Email                string `json:"email"`
  Username             string `json:"username"`
  Approved             bool   `json:"approved"`
  Sync                 bool   `json:"sync"`
  Passcode             string `json:"passcode"`
  DeviceName           string `json:"deviceName"`
  EncryptedLoginToken  string `json:"encryptedLoginToken"`
  EncryptedDeviceToken string `json:"encryptedDeviceToken"`
  IPAddress            string `json:"ipAddress"`
}

type PushEndpoint struct {
  isClosed      bool
  callbacks     []PushCallback
}
func (p *PushEndpoint) IsClosed() bool {
  return p.isClosed
}

func (p *PushEndpoint) Close() error {
  p.isClosed = true
  return nil
}

func (p *PushEndpoint) RegisterCallback(cb PushCallback) {
  for i, e := range p.callbacks {
    if e == nil {
      p.callbacks[i] = cb
      return
    }
  }
  p.callbacks = append(p.callbacks, cb)
}

func (p *PushEndpoint) RemoveCallback(cb PushCallback) {
  vcb := reflect.ValueOf(cb)
  for i, e := range p.callbacks {
    if reflect.ValueOf(e) == vcb {
      p.callbacks[i] = nil
    }
  }
}

func (p *PushEndpoint) Push(event *NotificationEvent) {
  for i, e := range p.callbacks {
    if e != nil {
      if e(event) {
        p.callbacks[i] = nil
      }
    }
  }
}

func (p *PushEndpoint) Write(_ []byte) error {
  return nil
}

type webSocketEndpoint struct {
  PushEndpoint
  conn *websocket.Conn
  encryptionKey []byte
}

func (wse *webSocketEndpoint) IsClosed() bool {
  if wse.conn == nil {
    return true
  }
  return wse.PushEndpoint.IsClosed()
}

func (wse *webSocketEndpoint) Write(data []byte) (err error) {
  if !wse.isClosed {
    _, err = wse.conn.Write(data)
  } else {
    err = NewKeeperError("Push endpoint is closed")
  }
  return
}

func (wse *webSocketEndpoint) Close() (err error) {
  if wse.conn != nil {
    return wse.conn.Close()
  }
  return wse.PushEndpoint.Close()
}

func (wse *webSocketEndpoint) readLoop() {
  buffer := make([]byte, 4*1024)
  for {
    if n, e := wse.conn.Read(buffer); e == nil {
      if (n > 0) {
        var data []byte
        if data, e = DecryptAesV2(buffer[:n], wse.encryptionKey); e == nil {
          event := new(NotificationEvent)
          if e = json.Unmarshal(data, event); e == nil {
            go wse.Push(event)
          }
        } else {
          glog.Warning("Push Notification decrypt error", e)
        }
      }
    } else {
      glog.Warning("Push Notification disconnected with error", e)
      break
    }
  }
  wse.isClosed = true
  if wse.conn != nil {
    wse.conn.Close()
    wse.conn = nil
  }
}
func NewWebSocketEndpoint(url string, key []byte) (result IPushEndpoint, err error) {
  var conn *websocket.Conn
  if conn, err = websocket.Dial(url, "", "http://localhost/"); err != nil {
    return
  }

  endpoint := &webSocketEndpoint{
    PushEndpoint: PushEndpoint{
      isClosed: false,
    },
    conn:     conn,
    encryptionKey: key,
  }

  go endpoint.readLoop()

  result = endpoint
  return
}
