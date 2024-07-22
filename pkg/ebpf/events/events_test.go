package events

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/go-logr/funcr"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
)

type mockLogger struct {
	logr.Logger
	messager []string
}

func (m *mockLogger) Info(msg string, keysAndValues ...interface{}) {
	m.messager = append(m.messager, msg)
}

func TestCapturePolicyEvents(t *testing.T) {
	mockLogger := &mockLogger{Logger: funcr.New(func(prefix, args string) {}, funcr.Options{})}
	ringBufferChan := make(chan []byte)

	utils.LocalCache = map[string]utils.Metadata{
		"192.168.0.1": {Name: "pod1", Namespace: "default"},
		"192.168.1.1": {Name: "pod2", Namespace: "kube-system"},
	}

	t.Run("Valid IPv4 Data", func(t *testing.T) {
		data := ringBufferDataV4_t{
			SourceIP:   3232235521, //192.168.0.1,
			SourcePort: 1234,
			DestIP:     3232235777, //192.168.1.1,
			DestPort:   80,
			Protocol:   6,
			Action:     1,
		}
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.LittleEndian, data)
		assert.NoError(t, err)

		go CapturePolicyEvents(ringBufferChan, mockLogger)
		ringBufferChan <- buf.Bytes()

		time.Sleep(1 * time.Second)

		expectedMsg := "Flow Info: Src IP 192.168.0.1 Src Name pod1 Src Namespace default Src Port 1234 Dest IP 192.168.1.1 Dest Name pod2 Dest Namespace kube-system Dest Port 80 Proto TCP Verdict ACCEPT"
		assert.Contains(t, mockLogger.messager, expectedMsg)
	})
}
