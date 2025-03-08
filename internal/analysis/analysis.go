package analysis

type Stats struct {
	Count       int
	TotalBytes  int64
	MinSize     int
	MaxSize     int
	PacketIDs   []int
	Description string
}
