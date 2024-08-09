package models

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

type Stringslice []string

func (ss *Stringslice) Scan(value interface{}) error {
	if value == nil {
		*ss = nil
		return nil
	}
	switch v := value.(type) {

	case string:
		*ss = strings.Split(v, " ")
		return nil
	case []byte:
		*ss = strings.Split(string(v), " ")
		return nil
	default:
		return fmt.Errorf("unsupported scan,storing driver.Value type %T into type %T", value, ss)
	}
}

func (ss Stringslice) Value() (driver.Value, error) {
	return strings.Join(ss, " "), nil
}

func (ss Stringslice) String() string {
	return strings.Join(ss, ", ")
}
