package sm

// CREDIT: https://github.com/dipeshdulal/statemachine/blob/master/statemachine.go

// MachineTransition transition map
type MachineTransition struct {
	Actions []func(current, next string)
	Cond    func(current, next string) bool
	To      string
}

// TransitionMap map with transitions
type TransitionMap map[string]MachineTransition

// MachineState is State of machine
type MachineState struct {
	On TransitionMap
}

// StateMap maps state
type StateMap map[string]MachineState

// Machine datatype
type Machine struct {
	ID          string
	Initial     string
	current     string
	States      StateMap
	Subscribers []func(curr, next string)
}

// IMachine machine interface
type IMachine interface {
	Transition(event string) string
	Current() string
}

// Current returns current state
func (m *Machine) Current() string {
	if m.current == "" {
		return m.Initial
	}
	return m.current
}

// Transition transitions to next state
func (m *Machine) Transition(event string) string {
	current := m.Current()
	transitions := m.States[current].On
	next := transitions[event].To

	if next != "" {
		callFuncts(m.Subscribers, current, next)

		if transitions[event].Cond != nil {
			if transitions[event].Cond(current, next) {
				m.current = next
				return next
			}
			return current
		}
		if transitions[event].Actions != nil {
			callFuncts(transitions[event].Actions, current, next)
		}

		m.current = next
		return next
	}
	return current
}

func callFuncts(functs []func(string, string), current, next string) {
	for _, funct := range functs {
		funct(current, next)
	}
}
