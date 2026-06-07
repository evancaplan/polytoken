package validator

type Hs256Validator struct {
}

func NewHs256Validator() *Hs256Validator {
	return &Hs256Validator{}
}

func (v *Hs256Validator) Validate(data string) (bool, error) {
	return false, nil
}
