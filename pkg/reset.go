package pkg

import "reflect"

func ClearStruct(s interface{}) {
	val := reflect.ValueOf(s).Elem()
	val.Set(reflect.Zero(val.Type()))
}
