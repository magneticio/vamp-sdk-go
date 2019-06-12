package events

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/magneticio/vamp-sdk-go/logging"
	"github.com/nats-io/go-nats"
	"github.com/nats-io/go-nats-streaming/pb"

	stan "github.com/nats-io/go-nats-streaming"
)

var log = logging.Logger()

type IEventBus interface {
	Publish(topic string, event *Event) error
}

type Events struct {
	connection        stan.Conn
	subscriptions     map[string]Subscription
	clusterID         string
	clientID          string
	natsURL           string
	caCert            string
	clientCert        string
	clientKey         string
	user              string
	password          string
	token             string
	natsTlsSkipVerify bool
}

type EventHandlerFunc func(event *Event) (handled bool, err error)

type Subscription struct {
	stan.Subscription
	options *SubscriptionOptions
}

type SubscriptionOption func(*SubscriptionOptions) error

type SubscriptionOptions struct {
	Name                 string
	UseQueue             bool
	IsDurable            bool
	MaxInflight          int
	StartTime            time.Time
	StartSequence        uint64
	StartPosition        StartPosition
	AcknowledgeWait      time.Duration
	AcknowledgeAutomatic bool
	UnsubscribeOnClose   bool
}

type StartPosition int32

const (
	StartPosition_NewOnly        StartPosition = 0
	StartPosition_LastReceived   StartPosition = 1
	StartPosition_TimeDeltaStart StartPosition = 2
	StartPosition_SequenceStart  StartPosition = 3
	StartPosition_First          StartPosition = 4
)

type Event struct {
	ID        uint64          `json:"-"`
	Timestamp int64           `json:"-"`
	Version   string          `json:"version,omitempty"`
	Type      string          `json:"type,omitempty"`
	Source    string          `json:"source,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

type VampEvent struct {
	ID        uint64          `json:"-"`
	Timestamp int64           `json:"-"`
	Version   string          `json:"version,omitempty"`
	Tags      []string        `json:"tags,omitempty"`
	Type      string          `json:"type,omitempty"`
	Payload   json.RawMessage `json:"nats_publisher_pulse,omitempty"`
}

func CreateEvent(typ string, source string, payload interface{}, metadata interface{}) *Event {
	event := &Event{Version: "1.0", Type: typ, Source: source}
	data, _ := json.Marshal(payload)
	event.Payload = json.RawMessage(data)

	data, _ = json.Marshal(metadata)
	event.Metadata = json.RawMessage(data)
	return event
}

func (events *Events) Init(natsURL, clusterID, clientID, caCert, clientCert, clientKey, user, password, token string, natsTlsSkipVerify bool) error {
	events.clusterID = clusterID
	events.clientID = clientID
	events.natsURL = natsURL
	events.caCert = caCert
	events.clientCert = clientCert
	events.clientKey = clientKey
	events.subscriptions = make(map[string]Subscription)
	events.user = user
	events.password = password
	events.token = token
	events.natsTlsSkipVerify = natsTlsSkipVerify
	return events.connect()
}

func (e *Events) connect() error {
	var err error
	var nc *nats.Conn
	var opts []nats.Option

	if e.caCert != "" || (e.clientCert != "" && e.clientKey != "") {
		opts = append(opts, nats.Secure(&tls.Config{InsecureSkipVerify: e.natsTlsSkipVerify, MinVersion: tls.VersionTLS12}))
	}
	if e.caCert != "" {
		opts = append(opts, nats.RootCAs(e.caCert))
	}
	if e.clientCert != "" && e.clientKey != "" {
		opts = append(opts, nats.ClientCert(e.clientCert, e.clientKey))
	}
	if e.user != "" && e.password != "" {
		opts = append(opts, nats.UserInfo(e.user, e.password))
	}
	if e.token != "" {
		opts = append(opts, nats.Token(e.token))
	}

	optionsBuilder := func(o *nats.Options) error {
		for _, opt := range opts {
			err := opt(o)
			if err != nil {
				return err
			}
		}
		return nil
	}

	nc, err = nats.Connect(e.natsURL, optionsBuilder)
	if err != nil {
		log.Infof("Can't connect to NATS. Make sure a NATS Streaming Server is running at: %s", e.natsURL)
		return err
	}

	e.connection, err = stan.Connect(e.clusterID, e.clientID, stan.NatsConn(nc), stan.Pings(5, 3), stan.SetConnectionLostHandler(e.connectionLostHandler), stan.ConnectWait(60*time.Second))
	if err != nil {
		log.Infof("Can't connect to NATS. Make sure a NATS Streaming Server is running at: %s", e.natsURL)
		return err
	}
	certs := ""
	if e.clientCert != "" && e.caCert != "" && e.clientKey != "" {
		certs = " using client certificate"
	}
	log.Infof("Connected to NATS %s clusterID: [%s] clientID: [%s]%s", e.natsURL, e.clusterID, e.clientID, certs)
	return nil
}

func (events *Events) Subscribe(topic string, handler EventHandlerFunc, option ...SubscriptionOption) error {
	options := SubscriptionOptions{
		Name:            topic,
		StartPosition:   StartPosition_NewOnly,
		MaxInflight:     1024,
		AcknowledgeWait: 30 * time.Second}
	for _, opt := range option {
		if opt != nil {
			if err := opt(&options); err != nil {
				return err
			}
		}
	}

	optionsBuilder := func(o *stan.SubscriptionOptions) error {
		if options.IsDurable {
			o.DurableName = options.Name
		}
		o.StartAt = pb.StartPosition(options.StartPosition)
		o.StartTime = options.StartTime
		o.StartSequence = options.StartSequence
		o.ManualAcks = !options.AcknowledgeAutomatic
		o.MaxInflight = options.MaxInflight
		o.AckWait = options.AcknowledgeWait
		return nil
	}

	messageHandler := func(message *stan.Msg) {
		log.Debugf("Received NATS Message %v", message)
		// Create Event from Message
		event, err := createEventFromMessage(message)
		if err != nil {
			log.Errorf("Error unmarshalling NATS message to event: %v", err)
			message.Ack()
		}

		// Handle event
		result, err := handler(event)

		if err != nil {
			if result {
				log.Errorf("Message[%d] non retryable error: %v", event.ID, err)
			} else {
				log.Warnf("Message[%d] retryable error: %v", event.ID, err)
			}
		}
		if !result {
			log.Infof("Message[%d] unhandled", event.ID)
			return
		}
		log.Infof("Message[%d] handled", event.ID)
		if err := message.Ack(); err != nil {
			log.Errorf("Acknowledge NATS Message failed %v", message)
		} else {
			log.Debugf("Acknowledged NATS Message %v", message)
		}
	}

	var err error
	var sub stan.Subscription
	if options.UseQueue {
		sub, err = events.connection.QueueSubscribe(topic, options.Name, messageHandler, optionsBuilder)
	} else {
		sub, err = events.connection.Subscribe(topic, messageHandler, optionsBuilder)
	}
	if err != nil {
		_ = events.connection.Close()
		log.Fatal(err)
	}
	events.subscriptions[topic] = Subscription{sub, &options}
	log.Infof("Subscribed: topic=[%s], group=[%s] durable=[%s]\n", topic, options.Name, options.Name)
	return nil
}

func (events *Events) Unsubscribe(name string) {
	if subscription, exists := events.subscriptions[name]; exists {
		if err := subscription.Unsubscribe(); err != nil {
			log.Fatalf("Unable to unsubscribe from topic %s: %v", name, err)
		}
		delete(events.subscriptions, name)
	}
}

func (events *Events) Publish(topic string, event *Event) error {
	data, _ := json.Marshal(event)
	if err := events.connection.Publish(topic, data); err != nil {
		return err
	}
	log.Debugf("Published: topic=[%s]: '%v'\n", topic, string(data))
	return nil
}

func (events *Events) Close() {
	for _, subscription := range events.subscriptions {
		if !subscription.options.IsDurable || subscription.options.UnsubscribeOnClose {
			subscription.Unsubscribe()
		}
	}
	_ = events.connection.Close()
}

// Options builder
func (events *Events) SubscriptionAcknowledgeWait(duration time.Duration) func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.AcknowledgeWait = duration
		return nil
	}
}

func (events *Events) SubscriptionAcknowledgeAutomatic() func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.AcknowledgeAutomatic = true
		return nil
	}
}

func (events *Events) SubscriptionName(name string) func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.Name = name
		return nil
	}
}

func (events *Events) SubscriptionUseQueue() func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.UseQueue = true
		return nil
	}
}

func (events *Events) SubscriptionUseDurability(unsubscribe bool) func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.IsDurable = true
		options.UnsubscribeOnClose = unsubscribe
		return nil
	}
}

func (events *Events) SubscriptionMaxInflight(inflight int) func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.MaxInflight = inflight
		return nil
	}
}

func (events *Events) SubscriptionStartAtNew() func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.StartPosition = StartPosition_NewOnly
		return nil
	}
}

func (events *Events) SubscriptionStartAtBeginning() func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.StartPosition = StartPosition_First
		return nil
	}
}

func (events *Events) SubscriptionStartAtLastReceived() func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.StartPosition = StartPosition_LastReceived
		return nil
	}
}

func (events *Events) SubscriptionStartAtTime(time time.Time) func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.StartTime = time
		options.StartPosition = StartPosition_TimeDeltaStart
		return nil
	}
}

func (events *Events) SubscriptionStartAtTimeDelta(ago time.Duration) func(options *SubscriptionOptions) error {
	return func(options *SubscriptionOptions) error {
		options.StartTime = time.Now().Add(-ago)
		options.StartPosition = StartPosition_TimeDeltaStart
		return nil
	}
}

func (events *Events) connectionLostHandler(_ stan.Conn, reason error) {
	err := events.connect()
	if err != nil {
		log.Infof("Error reconnecting to NATS...")
	}
}

func createEventFromMessage(message *stan.Msg) (*Event, error) {
	var err error
	var event *Event
	var vevent VampEvent
	if err := json.Unmarshal(message.Data, &vevent); err == nil {
		if vevent.Type == "event" { // Typical for a Vamp Event
			event, err = createEventFromVampEvent(vevent)
		}
	}

	if event == nil {
		err = json.Unmarshal(message.Data, &event)
		if err != nil {
			return nil, err
		}
	}
	event.ID = message.Sequence
	event.Timestamp = message.Timestamp
	return event, nil
}

var (
	GatewayEventSourcePrefix      = "gateways:"
	GatewayRouteEventTypePrefix   = "route:"
	GatewayRouteEventSourcePrefix = "routes:"
)

func createEventFromVampEvent(e VampEvent) (*Event, error) {
	event := &Event{Version: e.Version, Payload: e.Payload}
	metadata := make(map[string]interface{})
	hasEventType := false
	// Resolve tags
	for _, tag := range e.Tags {
		// Event Type
		if strings.HasPrefix(tag, GatewayRouteEventTypePrefix) {
			event.Type = tag
			hasEventType = true
		}
		// Assume all others as possible event type
		if !strings.HasPrefix(tag, "route") && !strings.HasPrefix(tag, "gateway") && !hasEventType {
			event.Type = tag
			hasEventType = true
		}
		// Event Source
		if strings.HasPrefix(tag, GatewayEventSourcePrefix) {
			event.Source = strings.TrimPrefix(tag, GatewayEventSourcePrefix)
		}
		// Event Metadata
		if strings.HasPrefix(tag, GatewayRouteEventSourcePrefix) {
			metadata["route"] = map[string]string{"source": strings.TrimPrefix(tag, GatewayRouteEventSourcePrefix)}
		}
	}
	if event.Type == "" || event.Source == "" {
		return nil, fmt.Errorf("Vamp Event is not convertable to a valid event")
	}
	data, _ := json.Marshal(metadata)
	event.Metadata = json.RawMessage(data)
	return event, nil
}
