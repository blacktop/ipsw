package sandbox

type OpGraph struct {
	List     []OperationNode
	Decision string
	Type     []string
	Not      bool
}

func NewOpGraph() *OpGraph {
	return &OpGraph{}
}

func (og *OpGraph) BuildGraph(name string, op OperationNode) error {

	return nil
}
