package analysis

// SeverityCounts holds aggregated finding counts by severity level.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

func (s SeverityCounts) Total() int {
	return s.Critical + s.High + s.Medium + s.Low + s.Info
}

func (s SeverityCounts) Add(other SeverityCounts) SeverityCounts {
	return SeverityCounts{
		Critical: s.Critical + other.Critical,
		High:     s.High + other.High,
		Medium:   s.Medium + other.Medium,
		Low:      s.Low + other.Low,
		Info:     s.Info + other.Info,
	}
}
