package unlock

import (
	"reflect"
	"testing"
	"time"

	"github.com/jack-work/hush/config"
)

// The keyring bound must not be raisable from hush.toml: no duration lives in
// the unlock or keyring configuration.
func TestNoUnlockSettingCanLengthenTheKeyringBound(t *testing.T) {
	duration := reflect.TypeOf(time.Duration(0))
	for _, typ := range []reflect.Type{reflect.TypeOf(config.UnlockConfig{}), reflect.TypeOf(config.KeyringConfig{})} {
		for i := 0; i < typ.NumField(); i++ {
			if f := typ.Field(i); f.Type == duration {
				t.Fatalf("%s.%s is a duration a config file could set", typ.Name(), f.Name)
			}
		}
	}
}
