package utils

import (
	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()
}

// ValidateStruct validates struct
func ValidateStruct(s interface{}) error {
	return validate.Struct(s)
}
