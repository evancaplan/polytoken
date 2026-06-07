package validator

type Rs256Validator struct {

}

func NewRs256Validator() *Rs256Validator {
	return &Rs256Validator{}
}

func (v *Rs256Validator) Validate(token string) (bool, error) {
	return false, nil
}
