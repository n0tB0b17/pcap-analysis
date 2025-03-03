package events

import "fmt"

type EventTypes string

const (
	ProtocolDetected        EventTypes = "PROTOCOL_DETECTED"
	TCPPacketEvent          EventTypes = "TCP_PACKET_EVENT"
	UDPPacketEvent          EventTypes = "UDP_PACKET_EVENT"
	UnknownProtocolDetected EventTypes = "UNKNOWN_PROTOCOL_DETECTED"
)

type Event interface {
	EventType() string
}

type EventBus struct {
	subscribers  map[string][]chan Event
	eventChannel chan Event
}

func NewEventBus() *EventBus {
	return &EventBus{
		eventChannel: make(chan Event),
		subscribers:  make(map[string][]chan Event),
	}
}

func (bus *EventBus) Publish(e Event) {
	bus.eventChannel <- e
}

func (bus *EventBus) Subscribe(eventType EventTypes, subscriberChannel chan Event) {
	bus.subscribers[string(eventType)] = append(bus.subscribers[string(eventType)], subscriberChannel)
}

func (bus *EventBus) StartBus() {
	go func() {
		for eve := range bus.eventChannel {
			eventType := eve.EventType()
			if subscriber, ok := bus.subscribers[eventType]; ok {
				for _, subChannel := range subscriber {
					select {
					case subChannel <- eve:
					default:
						fmt.Println("subscribe channel is full")
					}
				}
			}
		}
	}()
}

func (bus *EventBus) StopBus() {
	close(bus.eventChannel)
}
