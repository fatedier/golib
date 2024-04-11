package mux

type MatchFunc func(data []byte) (match bool)

var (
	HTTPSNeedBytesNum uint32 = 1
	HTTPNeedBytesNum  uint32 = 3
	YamuxNeedBytesNum uint32 = 2
)

var HTTPSMatchFunc MatchFunc = func(data []byte) bool {
	if len(data) < int(HTTPSNeedBytesNum) {
		return false
	}
	return data[0] == 0x16
}

// From https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
var httpHeadBytes = map[string]struct{}{
	"GET": {},
	"HEA": {},
	"POS": {},
	"PUT": {},
	"DEL": {},
	"CON": {},
	"OPT": {},
	"TRA": {},
	"PAT": {},
}

var HTTPMatchFunc MatchFunc = func(data []byte) bool {
	if len(data) < int(HTTPNeedBytesNum) {
		return false
	}

	_, ok := httpHeadBytes[string(data[:3])]
	return ok
}

// YamuxMatchFunc is a match function for yamux.
// From https://github.com/hashicorp/yamux/blob/master/spec.md
var YamuxMatchFunc MatchFunc = func(data []byte) bool {
	if len(data) < int(YamuxNeedBytesNum) {
		return false
	}

	if data[0] == 0 && data[1] <= 0x3 {
		return true
	}
	return false
}
